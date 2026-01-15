#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本 (终极版)
功能：自动签到 + 余额查询 + GitHub可视化 + HTML邮件报表 + 随机延迟
"""

import asyncio
import hashlib
import json
import os
import sys
import random
from datetime import datetime

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from utils.config import AccountConfig, AppConfig, load_accounts_config
from utils.notify import notify

load_dotenv()

BALANCE_HASH_FILE = 'balance_hash.txt'

# --- HTML 邮件模板 ---
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; }
  .container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
  .header { text-align: center; margin-bottom: 20px; border-bottom: 2px solid #4f46e5; padding-bottom: 10px; }
  .title { font-size: 24px; font-weight: bold; color: #4f46e5; margin: 0; }
  .time { color: #888; font-size: 14px; margin-top: 5px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
  th { background-color: #f8fafc; color: #64748b; font-weight: 600; text-align: left; padding: 12px; border-bottom: 1px solid #e2e8f0; font-size: 14px; }
  td { padding: 12px; border-bottom: 1px solid #f1f5f9; font-size: 14px; }
  .status-success { color: #10b981; font-weight: bold; background-color: #ecfdf5; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
  .status-fail { color: #ef4444; font-weight: bold; background-color: #fef2f2; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
  .balance { font-family: "JetBrains Mono", monospace; font-weight: 600; color: #0f172a; }
  .footer { text-align: center; font-size: 12px; color: #999; margin-top: 20px; border-top: 1px solid #eee; padding-top: 10px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="title">AnyRouter 签到日报</div>
    <div class="time">📅 {{DATE_TIME}}</div>
  </div>
  
  <table>
    <thead>
      <tr>
        <th>账号</th>
        <th>状态</th>
        <th>当前余额</th>
        <th>已用</th>
      </tr>
    </thead>
    <tbody>
      {{TABLE_ROWS}}
    </tbody>
  </table>
  
  <div class="footer">
    Power by AnyRouter-CheckIn · <a href="https://github.com/songqizhou/anyrouter-check-in" style="color:#999;text-decoration:none;">GitHub</a>
  </div>
</div>
</body>
</html>
"""

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
    """使用 Playwright 获取 WAF cookies"""
    print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')
    async with async_playwright() as p:
        import tempfile
        with tempfile.TemporaryDirectory() as temp_dir:
            context = await p.chromium.launch_persistent_context(
                user_data_dir=temp_dir,
                headless=True,
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
                viewport={'width': 1920, 'height': 1080},
                args=['--disable-blink-features=AutomationControlled', '--no-sandbox']
            )
            page = await context.new_page()
            try:
                await page.goto(login_url, wait_until='networkidle')
                try:
                    await page.wait_for_function('document.readyState === "complete"', timeout=5000)
                except Exception:
                    await page.wait_for_timeout(3000)
                
                cookies = await page.context.cookies()
                waf_cookies = {}
                for cookie in cookies:
                    if cookie.get('name') in required_cookies and cookie.get('value'):
                        waf_cookies[cookie.get('name')] = cookie.get('value')
                
                await context.close()
                return waf_cookies if waf_cookies else None
            except Exception as e:
                print(f'[FAILED] {account_name}: Error getting WAF cookies: {e}')
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
                    'display': f':money: Balance: ${quota}, Used: ${used_quota}',
                }
        return {'success': False, 'error': f'HTTP {response.status_code}'}
    except Exception as e:
        return {'success': False, 'error': str(e)[:50]}

async def prepare_cookies(account_name: str, provider_config, user_cookies: dict) -> dict | None:
    waf_cookies = {}
    if provider_config.needs_waf_cookies():
        login_url = f'{provider_config.domain}{provider_config.login_path}'
        waf_cookies = await get_waf_cookies_with_playwright(account_name, login_url, provider_config.waf_cookie_names)
        if not waf_cookies: return None
    return {**waf_cookies, **user_cookies}

def execute_check_in(client, account_name: str, provider_config, headers: dict):
    """执行签到请求"""
    checkin_headers = headers.copy()
    checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})
    sign_in_url = f'{provider_config.domain}{provider_config.sign_in_path}'
    response = client.post(sign_in_url, headers=checkin_headers, timeout=30)
    
    if response.status_code == 200:
        try:
            result = response.json()
            if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
                return True
            print(f'[FAILED] {account_name}: {result.get("msg", "Unknown error")}')
            return False
        except:
            return 'success' in response.text.lower()
    return False

async def check_in_account(account: AccountConfig, account_index: int, app_config: AppConfig):
    """单账号处理：先签到 -> 后查余额"""
    account_name = account.get_display_name(account_index)
    print(f'\n[PROCESSING] {account_name}...')
    
    provider_config = app_config.get_provider(account.provider)
    if not provider_config: return False, None

    user_cookies = parse_cookies(account.cookies)
    all_cookies = await prepare_cookies(account_name, provider_config, user_cookies)
    if not all_cookies: return False, None

    client = httpx.Client(http2=True, timeout=30.0)
    try:
        client.cookies.update(all_cookies)
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
            'Referer': provider_config.domain,
            'Origin': provider_config.domain,
            provider_config.api_user_key: account.api_user,
        }

        # 1. 签到
        check_in_success = True
        if provider_config.needs_manual_check_in():
            check_in_success = execute_check_in(client, account_name, provider_config, headers)
            if check_in_success: await asyncio.sleep(1) # 等待数据同步
        
        # 2. 查余额
        user_info_url = f'{provider_config.domain}{provider_config.user_info_path}'
        user_info = get_user_info(client, headers, user_info_url)
        
        if user_info and user_info.get('success'):
            print(f"[INFO] {account_name} {user_info['display']}")
            
        return check_in_success, user_info
    except Exception as e:
        print(f'[FAILED] {account_name}: {e}')
        return False, None
    finally:
        client.close()

def generate_html_report(results):
    """生成美观的 HTML 邮件内容"""
    rows = ""
    for res in results:
        status_class = "status-success" if res['success'] else "status-fail"
        status_text = "✅ 签到成功" if res['success'] else "❌ 签到失败"
        quota = f"${res.get('quota', 0)}" if res.get('quota') is not None else "-"
        used = f"${res.get('used', 0)}" if res.get('used') is not None else "-"
        
        rows += f"""
        <tr>
          <td>{res['name']}</td>
          <td><span class="{status_class}">{status_text}</span></td>
          <td class="balance">{quota}</td>
          <td class="balance" style="color: #64748b;">{used}</td>
        </tr>
        """
    
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return HTML_TEMPLATE.replace("{{DATE_TIME}}", current_time).replace("{{TABLE_ROWS}}", rows)

def write_github_summary(results):
    """生成 GitHub Action 摘要"""
    if not os.getenv('GITHUB_STEP_SUMMARY'): return
    markdown = "### 🚀 AnyRouter 签到结果汇总\n\n| 账号 | 状态 | 余额 | 已用 | 备注 |\n| :--- | :---: | :---: | :---: | :--- |\n"
    for res in results:
        icon = "✅" if res['success'] else "❌"
        quota = f"${res.get('quota', '-')}"
        used = f"${res.get('used', '-')}"
        markdown += f"| {res['name']} | {icon} | {quota} | {used} | {res.get('msg', '')} |\n"
    try:
        with open(os.getenv('GITHUB_STEP_SUMMARY'), 'a', encoding='utf-8') as f: f.write(markdown)
    except: pass

async def main():
    print('[SYSTEM] AnyRouter Auto Check-in Started')
    
    # === 随机延迟 (模拟真人) ===
    # 0 到 30分钟 随机延迟
    delay = random.randint(1, 600)
    print(f'[WAIT] Random delay: {delay} seconds...')
    await asyncio.sleep(delay)
    
    app_config = AppConfig.load_from_env()
    accounts = load_accounts_config()
    if not accounts: sys.exit(1)

    summary_results = []
    text_notify_lines = []
    success_count = 0

    for i, account in enumerate(accounts):
        account_name = account.get_display_name(i)
        success, user_info = await check_in_account(account, i, app_config)
        
        if success: success_count += 1
        
        # 收集数据用于生成报表
        res = {
            'name': account_name,
            'success': success,
            'quota': user_info.get('quota') if user_info else None,
            'used': user_info.get('used_quota') if user_info else None,
            'msg': 'OK' if success else user_info.get('error', 'Unknown Error')
        }
        summary_results.append(res)
        
        # 收集纯文本通知
        status_icon = '[SUCCESS]' if success else '[FAIL]'
        line = f"{status_icon} {account_name}"
        if user_info and user_info.get('success'):
            line += f"\n💰 余额: ${res['quota']} (已用: ${res['used']})"
        elif user_info:
            line += f"\n⚠️ {res['msg']}"
        text_notify_lines.append(line)

    # 1. 生成 GitHub 摘要
    write_github_summary(summary_results)
    
    # 2. 发送通知
    # A. 专门给邮箱发 HTML 报表 (如果配置了邮箱)
    if os.getenv('EMAIL_USER'):
        print('[NOTIFY] Sending HTML report to email...')
        html_content = generate_html_report(summary_results)
        try:
            notify.send_email("AnyRouter 签到日报", html_content, msg_type='html')
        except Exception as e:
            print(f'[ERROR] Failed to send email: {e}')

    # B. 给其他渠道 (钉钉/TG等) 发纯文本
    # 注意：这里我们过滤掉 'Email' 以免发两遍 (一遍HTML一遍Text)
    # 但由于 notify.push_message 比较简单，我们手动处理一下
    
    full_text = f"📅 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n" + "\n\n".join(text_notify_lines)
    
    # 简单的分发逻辑：如果配置了其他Webhook，手动发送
    # 这里我们还是调用 push_message，但如果你配置了邮箱，push_message 也会再发一封纯文本邮件
    # 如果你不介意收到两封邮件（一封HTML表格，一封纯文本），可以直接保留下面这行：
    # notify.push_message('AnyRouter 签到结果', full_text, msg_type='text')
    
    # 稍微优化一下：手动触发除 Email 外的通知
    print('[NOTIFY] Sending text notification to other channels...')
    if os.getenv('DINGDING_WEBHOOK'): notify.send_dingtalk('AnyRouter', full_text)
    if os.getenv('TELEGRAM_BOT_TOKEN'): notify.send_telegram('AnyRouter', full_text)
    if os.getenv('FEISHU_WEBHOOK'): notify.send_feishu('AnyRouter', full_text)
    if os.getenv('WEIXIN_WEBHOOK'): notify.send_wecom('AnyRouter', full_text)
    if os.getenv('PUSHPLUS_TOKEN'): notify.send_pushplus('AnyRouter', full_text)
    # ... 其他渠道可以按需添加 ...

    sys.exit(0 if success_count > 0 else 1)

def run_main():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(1)
    except Exception as e:
        print(f'\n[FAILED] Error: {e}')
        sys.exit(1)

if __name__ == '__main__':
    run_main()
