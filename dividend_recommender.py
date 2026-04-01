"""
Dividend Recommender

- Fetches a universe of tickers (default: S&P 500 from Wikipedia) or from a user file
- Uses Yahoo Finance (yfinance) to compute dividend yield, dividend history stability,
  payout ratio, volatility and dividend growth
- Filters for stable, reasonably-sized, dividend-paying companies and ranks them
- Outputs top-N recommendations (CSV + printed table) and can email results

Not financial advice. Use at your own risk.
"""

import argparse
import datetime
import logging
import math
import os
import smtplib
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage

import numpy as np
import pandas as pd
import yfinance as yf

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


def get_sp500_tickers():
    url = 'https://en.wikipedia.org/wiki/List_of_S%26P_500_companies'
    try:
        tables = pd.read_html(url)
        df = tables[0]
        tickers = df['Symbol'].tolist()
        tickers = [t.replace('.', '-') for t in tickers]
        return tickers
    except Exception as e:
        logging.error('Failed to fetch S&P 500 tickers: %s', e)
        return []


def fetch_ticker_info(ticker, years_div=5):
    result = {'ticker': ticker}
    try:
        tk = yf.Ticker(ticker)
        info = tk.info
        result['shortName'] = info.get('shortName')
        result['sector'] = info.get('sector')
        result['marketCap'] = info.get('marketCap') or 0
        # dividendYield from info is often in decimal (e.g., 0.035)
        result['dividendYield'] = info.get('dividendYield') or 0
        result['payoutRatio'] = info.get('payoutRatio') or None

        # price history for volatility and returns
        end = datetime.datetime.today()
        start = end - datetime.timedelta(days=365)
        hist = tk.history(start=start, end=end, auto_adjust=False)
        if not hist.empty:
            hist = hist.dropna()
            close = hist['Close']
            returns = close.pct_change().dropna()
            result['volatility'] = float(returns.std()) if not returns.empty else None
            result['oneYearReturn'] = float((close[-1] / close[0] - 1)) if len(close) > 1 else None
        else:
            result['volatility'] = None
            result['oneYearReturn'] = None

        # dividend history for last N years
        div_hist = tk.dividends
        if div_hist is None or div_hist.empty:
            result['dividend_years'] = 0
            result['dividend_growth_5y'] = None
            result['annual_dividends'] = {}
        else:
            # group by year
            div_by_year = div_hist.groupby(div_hist.index.year).sum()
            # consider last `years_div` calendar years
            years = sorted(div_by_year.index)
            recent_years = [y for y in years if y >= (datetime.date.today().year - years_div + 1)]
            annual = {int(year): float(div_by_year.loc[year]) for year in recent_years if year in div_by_year.index}
            result['annual_dividends'] = annual
            result['dividend_years'] = len([a for a in annual.values() if a > 0])
            if len(annual) >= 2:
                sorted_years = sorted(annual.keys())
                first = annual[sorted_years[0]]
                last = annual[sorted_years[-1]]
                if first and first > 0:
                    result['dividend_growth_5y'] = (last / first - 1)
                else:
                    result['dividend_growth_5y'] = None
            else:
                result['dividend_growth_5y'] = None

    except Exception as e:
        logging.debug('Failed to fetch %s: %s', ticker, e)
    return result


def score_universe(df):
    # Build normalized scores for components; handle missing values
    df = df.copy()

    # Fill NaNs for calculations
    df['dividendYield'] = df['dividendYield'].replace([None], 0).astype(float)
    df['dividend_years'] = df['dividend_years'].replace([None], 0).astype(float)
    df['dividend_growth_5y'] = df['dividend_growth_5y'].replace([None], np.nan).astype(float)
    df['payoutRatio'] = df['payoutRatio'].replace([None], np.nan).astype(float)
    df['volatility'] = df['volatility'].replace([None], np.nan).astype(float)

    # Define sensible defaults
    # Higher yield better, more dividend years better, higher growth better, lower payout better, lower vol better

    def minmax(series):
        if series.dropna().empty:
            return pd.Series(0, index=series.index)
        smin = series.min()
        smax = series.max()
        if math.isclose(smin, smax):
            return pd.Series(0.5, index=series.index)
        return (series - smin) / (smax - smin)

    y_score = minmax(df['dividendYield'])
    stability_score = minmax(df['dividend_years'])
    growth_score = minmax(df['dividend_growth_5y'].fillna(-1))  # missing growth => low
    payout_score = 1 - minmax(df['payoutRatio'].fillna(df['payoutRatio'].max() if not df['payoutRatio'].dropna().empty else 1))
    vol_score = 1 - minmax(df['volatility'].fillna(df['volatility'].max() if not df['volatility'].dropna().empty else 1))

    # weights
    w = {'yield': 0.4, 'stability': 0.2, 'growth': 0.2, 'payout': 0.1, 'vol': 0.1}

    df['score'] = (
        w['yield'] * y_score
        + w['stability'] * stability_score
        + w['growth'] * growth_score
        + w['payout'] * payout_score
        + w['vol'] * vol_score
    )

    return df.sort_values('score', ascending=False)


def recommend(universe=None, top_n=5, min_yield=0.03, min_div_years=4, min_marketcap=1e9, threads=8):
    if universe is None:
        logging.info('Fetching S&P 500 tickers as universe')
        universe = get_sp500_tickers()
    else:
        logging.info('Using provided universe of %d tickers', len(universe))

    results = []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(fetch_ticker_info, t): t for t in universe}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)

    df = pd.DataFrame(results)
    if df.empty:
        logging.error('No data fetched. Exiting.')
        return pd.DataFrame(), None

    # Apply basic filters
    df = df[df['dividendYield'] >= min_yield]
    df = df[df['dividend_years'] >= min_div_years]
    df = df[df['marketCap'] >= min_marketcap]

    if df.empty:
        logging.warning('No tickers passed filters. Lower thresholds or provide a custom universe.')
        return pd.DataFrame(), None

    scored = score_universe(df)
    top = scored.head(top_n)

    # Output
    now = datetime.datetime.now().strftime('%Y%m%d')
    out_file = f'recommendations_{now}.csv'
    top.to_csv(out_file, index=False)
    logging.info('Saved recommendations to %s', out_file)
    return top, out_file


def send_email(recipients, subject, body, attachment_path=None):
    smtp_server = os.environ.get('SMTP_SERVER')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USERNAME')
    smtp_pass = os.environ.get('SMTP_PASSWORD')
    email_from = os.environ.get('EMAIL_FROM', smtp_user)

    if not smtp_server:
        raise RuntimeError('SMTP_SERVER not configured')

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = email_from
    msg['To'] = ', '.join(recipients)
    msg.set_content(body)

    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, 'rb') as f:
            data = f.read()
        msg.add_attachment(data, maintype='application', subtype='octet-stream', filename=os.path.basename(attachment_path))

    # Connect and send
    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:
        server.starttls()
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)


def main():
    parser = argparse.ArgumentParser(description='Dividend stock recommender: daily top dividend picks')
    parser.add_argument('--universe-file', help='Path to file with tickers (one per line)', default=None)
    parser.add_argument('--top', type=int, default=5)
    parser.add_argument('--min-yield', type=float, default=0.03)
    parser.add_argument('--min-div-years', type=int, default=4)
    parser.add_argument('--min-marketcap', type=float, default=1e9)
    parser.add_argument('--threads', type=int, default=8)
    args = parser.parse_args()

    universe = None
    if args.universe_file:
        try:
            with open(args.universe_file) as f:
                universe = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logging.error('Unable to read universe file: %s', e)
            sys.exit(1)

    top, out_file = recommend(universe=universe, top_n=args.top, min_yield=args.min_yield, min_div_years=args.min_div_years, min_marketcap=args.min_marketcap, threads=args.threads)

    if top is not None and not top.empty:
        display_cols = ['ticker', 'shortName', 'sector', 'marketCap', 'dividendYield', 'dividend_years', 'dividend_growth_5y', 'payoutRatio', 'volatility', 'score']
        print(top[display_cols].to_string(index=False))

        # Send email if SMTP settings are provided via environment variables
        smtp_server = os.environ.get('SMTP_SERVER')
        if smtp_server:
            try:
                recipients = os.environ.get('EMAIL_TO')
                if not recipients:
                    logging.warning('SMTP configured but EMAIL_TO not set; skipping email.')
                else:
                    subject = f"Daily Dividend Picks ({datetime.date.today().isoformat()})"
                    body = 'Please find attached the top dividend picks generated today.'
                    send_email(recipients.split(','), subject, body, attachment_path=out_file)
                    logging.info('Email notification sent to %s', recipients)
            except Exception as e:
                logging.error('Failed to send email notification: %s', e)
    else:
        print('No recommendations generated with current filters.')


if __name__ == '__main__':
    main()
