#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
(已优化：先签到后查余额 + GitHub Action 可视化表格 + 强制通知)
"""

import asyncio
import hashlib
import json
import os
import sys
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'


def load_balance_hash():
    """加载余额hash"""
    try:
        if os.path.exists(BALANCE_HASH_FILE):
            with open(BALANCE_HASH_FILE, 'r', encoding='utf-8') as f:
                return f.read().strip()
    except Exception:
        pass
    return None


def save_balance_hash(balance_hash):
    """保存余额hash"""
    try:
        with open(BALANCE_HASH_FILE, 'w', encoding='utf-8') as f:
            f.write(balance_hash)
    except Exception as e:
        print(f'Warning: Failed to save balance hash: {e}')


def generate_balance_hash(balances):
    """生成余额数据的hash"""
    simple_balances = {k: v['quota'] for k, v in balances.items()} if balances else {}
    balance_json = json.dumps(simple_balances, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(balance_json.encode('utf-8')).hexdigest()[:16]


def parse_cookies(cookies_data):
    """解析 cookies 数据"""
    if isinstance(cookies_data, dict):
        return cookies_data

    if isinstance(cookies_data, str):
        cookies_dict = {}
        for cookie in cookies_data.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies_dict[key] = value
        return cookies_dict
    return {}


async def get_waf_cookies_with_playwright(account_name: str, login_url: str, required_cookies: list[str]):
    """使用 Playwright 获取 WAF cookies（隐私模式）"""
    print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

    async with async_playwright() as p:
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            context = await p.chromium.launch_persistent_context(
                user_data_dir=temp_dir,
                headless=True, # 这里可以改回 True，GitHub Action 中必须是 True 或支持无头
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                viewport={'width': 1920, 'height': 1080},
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                    '--no-sandbox',
                ],
            )

            page = await context.new_page()

            try:
                print(f'[PROCESSING] {account_name}: Access login page to get initial cookies...')

                await page.goto(login_url, wait_until='networkidle')

                try:
                    await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                except Exception:
                    await page.wait_for_timeout(3000)

                cookies = await page.context.cookies()

                waf_cookies = {}
                for cookie in cookies:
                    cookie_name = cookie.get('name')
                    cookie_value = cookie.get('value')
                    if cookie_name in required_cookies and cookie_value is not None:
                        waf_cookies[cookie_name] = cookie_value

                print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies')

                missing_cookies = [c for c in required_cookies if c not in waf_cookies]

                if missing_cookies:
                    print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
                    await context.close()
                    return None

                print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')

                await context.close()

                return waf_cookies

            except Exception as e:
                print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
                await context.close()
                return None


def get_user_info(client, headers, user_info_url: str):
    """获取用户信息"""
    try:
        response = client.get(user_info_url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                user_data = data.get('data', {})
                quota = round(user_data.get('quota', 0) / 500000, 2)
                used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
                return {
                    'success': True,
                    'quota': quota,
                    'used_quota': used_quota,
                    'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
                }
        return {'success': False, 'error': f'Failed to get user info: HTTP {response.status_code}'}
    except Exception as e:
        return {'success': False, 'error': f'Failed to get user info: {str(e)[:50]}...'}


async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
    """准备请求所需的 cookies（可能包含 WAF cookies）"""
    waf_cookies = {}

    if provider_config.needs_waf_cookies():
        login_url = f'{provider_config.domain}{provider_config.login_path}'
        waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
        if not waf_cookies:
            print(f'[FAILED] {account_name}: Unable to get WAF cookies')
            return None
    else:
        print(f'[INFO] {account_name}: Bypass WAF not required, using user cookies directly')

    return {**waf_cookies, **user_cookies}


def execute_check_in(client, account_name: str, provider_config, headers: dict):
    """执行签到请求"""
    print(f'[NETWORK] {account_name}: Executing check-in')

    checkin_headers = headers.copy()
    checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

    sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
    response = client.post(sign_in_url, headers=checkin_headers, timeout=30)

    print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

    if response.status_code == 200:
        try:
            result = response.json()
            if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
                print(f'[SUCCESS] {account_name}: Check-in successful!')
                return True
            else:
                error_msg = result.get('msg', result.get('message', 'Unknown error'))
                print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
                return False
        except json.JSONDecodeError:
            if 'success' in response.text.lower():
                print(f'[SUCCESS] {account_name}: Check-in successful!')
                return True
            else:
                print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
                return False
    else:
        print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
        return False


async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
    """为单个账号执行签到操作（修改：先签到，再查余额）"""
    account_name = account.get_display_name(account_index)
    print(f'\n[PROCESSING] Starting to process {account_name}')

    provider_config = app_config.get_provider(account.provider)
    if not provider_config:
        print(f'[FAILED] {account_name}: Provider "{account.provider}" not found in configuration')
        return False, None

    print(f'[INFO] {account_name}: Using provider "{account.provider}" ({provider_config.domain})')

    user_cookies = parse_cookies(account.cookies)
    if not user_cookies:
        print(f'[FAILED] {account_name}: Invalid configuration format')
        return False, None

    all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
    if not all_cookies:
        return False, None

    client = httpx.Client(http2=True, timeout=30.0)

    try:
        client.cookies.update(all_cookies)

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Referer': provider_config.domain,
            'Origin': provider_config.domain,
            'Connection': 'keep-alive',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            provider_config.api_user_key: account.api_user,
        }

        # --- 修改开始：先执行签到 ---
        check_in_success = True
        if provider_config.needs_manual_check_in():
            check_in_success = execute_check_in(client, account_name, provider_config, headers)
            # 稍作等待，确保服务器数据同步
            if check_in_success:
                await asyncio.sleep(1)
        else:
            print(f'[INFO] {account_name}: Manual check-in skipped (auto trigger)')

        # --- 修改：签到后再查询用户信息（获取最新余额） ---
        user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
        user_info = get_user_info(client, headers, user_info_url)
        
        if user_info and user_info.get('success'):
            print(f"[INFO] {account_name} Latest: {user_info['display']}")
        elif user_info:
            print(user_info.get('error', 'Unknown error'))

        # 返回结果
        if provider_config.needs_manual_check_in():
             return check_in_success, user_info
        else:
             return True, user_info

    except Exception as e:
        print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
        return False, None
    finally:
        client.close()


def write_github_summary(results):
    """生成 GitHub Action 摘要表格"""
    if not os.getenv('GITHUB_STEP_SUMMARY'):
        return

    markdown = "### 🚀 AnyRouter 签到结果汇总\n\n"
    markdown += "| 账号 (Account) | 状态 (Status) | 余额 (Balance) | 已用 (Used) | 备注 (Note) |\n"
    markdown += "| :--- | :---: | :---: | :---: | :--- |\n"

    for res in results:
        status_icon = "✅ 成功" if res['success'] else "❌ 失败"
        quota = f"${res.get('quota', 0)}" if res.get('quota') is not None else "-"
        used = f"${res.get('used', 0)}" if res.get('used') is not None else "-"
        msg = res.get('msg', '')
        
        markdown += f"| {res['name']} | {status_icon} | {quota} | {used} | {msg} |\n"

    try:
        with open(os.getenv('GITHUB_STEP_SUMMARY'), 'a', encoding='utf-8') as f:
            f.write(markdown)
        print("[SYSTEM] GitHub Summary generated successfully.")
    except Exception as e:
        print(f"[WARN] Failed to generate GitHub Summary: {e}")


async def main():
    """主函数"""
    print('[SYSTEM] AnyRouter.top multi-account auto check-in script started (using Playwright)')
    print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

    app_config = AppConfig.load_from_env()
    print(f'[INFO] Loaded {len(app_config.providers)} provider configuration(s)')

    accounts = load_accounts_config()
    if not accounts:
        print('[FAILED] Unable to load account configuration, program exits')
        sys.exit(1)

    print(f'[INFO] Found {len(accounts)} account configurations')

    last_balance_hash = load_balance_hash()

    success_count = 0
    total_count = len(accounts)
    notification_content = []
    current_balances = {}
    summary_results = [] # 用于生成 GitHub 表格
    
    # 强制每次都发送通知（如果不想强制，改为 False）
    need_notify = True 

    for i, account in enumerate(accounts):
        account_key = f'account_{i + 1}'
        account_name = account.get_display_name(i)
        
        try:
            success, user_info = await check_in_account(account, i, app_config)
            
            # 记录结果用于表格
            result_item = {
                'name': account_name,
                'success': success,
                'quota': None,
                'used': None,
                'msg': 'OK' if success else 'Failed'
            }

            if success:
                success_count += 1
            
            # 构建单条通知内容
            status_tag = '[SUCCESS]' if success else '[FAIL]'
            account_msg = f'{status_tag} {account_name}'
            
            if user_info and user_info.get('success'):
                current_quota = user_info['quota']
                current_used = user_info['used_quota']
                current_balances[account_key] = {'quota': current_quota, 'used': current_used}
                
                # 填充表格数据
                result_item['quota'] = current_quota
                result_item['used'] = current_used
                
                # 填充通知数据 (直接把余额加上去)
                account_msg += f'\n{user_info["display"]}'
            elif user_info:
                err = user_info.get("error", "Unknown error")
                account_msg += f'\nError: {err}'
                result_item['msg'] = err
            
            summary_results.append(result_item)
            notification_content.append(account_msg)

        except Exception as e:
            print(f'[FAILED] {account_name} processing exception: {e}')
            notification_content.append(f'[FAIL] {account_name} exception: {str(e)[:50]}...')
            summary_results.append({
                'name': account_name,
                'success': False,
                'msg': str(e)[:50]
            })

    # 生成可视化的 GitHub Summary 表格
    write_github_summary(summary_results)

    # 计算 Hash 仅为了记录日志，不再阻止通知
    current_balance_hash = generate_balance_hash(current_balances) if current_balances else None
    if current_balance_hash:
        save_balance_hash(current_balance_hash)
        if last_balance_hash != current_balance_hash:
            print('[INFO] Balance change detected.')
    
    # 发送通知
    if need_notify and notification_content:
        summary = [
            f'[STATS] Success: {success_count}/{total_count}',
            f'[TIME] {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
        ]
        
        full_notify_content = '\n\n'.join(['\n'.join(notification_content), '\n'.join(summary)])
        
        print('\n--- Notification Content ---')
        print(full_notify_content)
        print('----------------------------\n')
        
        notify.push_message('AnyRouter Check-in Report', full_notify_content, msg_type='text')
    else:
        print('[INFO] Notification skipped.')

    sys.exit(0 if success_count > 0 else 1)


def run_main():
    """运行主函数的包装函数"""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[WARNING] Program interrupted by user')
        sys.exit(1)
    except Exception as e:
        print(f'\n[FAILED] Error occurred during program execution: {e}')
        sys.exit(1)


if __name__ == '__main__':
    run_main()
