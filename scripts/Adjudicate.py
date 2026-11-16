"""Final-label adjudication: scam | legitimate | review.

Evidence order (first match wins):
  0. manual decisions   - rows a human/Claude read one by one (data/interim/manual_decisions.csv)
  1. family decisions   - pattern families that were read in bulk (digital-arrest scripts, synthetic notices, garbled translations)
  2. scam evidence      - triage_rules signals + extended families (look-alike links, advance fees, income lures, ...)
  3. legitimate evidence- genuine OTP, transaction alert, order status, anti-fraud advisory, service notice, plain promo
  4. source label       - source says legitimate and nothing contradicts it
  5. review             - everything else (genuinely ambiguous)

Definition (docs/annotation_guidelines.md): scam = intent to deceive / steal money / obtain OTP, passwords, bank details /
impersonate an organisation / trick into a fraudulent action. Ordinary adverts and unwanted promotions are legitimate.
Grounding: RBI KYC/OTP advisories, I4C/MHA "digital arrest" advisories, PIB Fact Check (India Post address SMS),
TRAI SMS-header rules (-P/-S/-T/-G), plus the families read directly from the data.
"""
import re
from pathlib import Path
import pandas as pd
try:
    from .triage_rules import signals as base_signals, URL, PHONE
except ImportError:
    from triage_rules import signals as base_signals, URL, PHONE

# ------------------------------------------------------------------ helpers
HOST_RE = re.compile(r"(?:https?://)?((?:[a-z0-9][a-z0-9-]*\.)+[a-z]{2,})(?::\d+)?(?:/|\b)")
SUS_TLD = {"ml","ga","gq","cf","ws","xyz","top","live","online","site","pay","bill","link","track","info","click","icu","cc","tk","ru","pics","shop","vip",
           "club","work","buzz","fit","rest","life","bond","today","store","cfd","sbs","cyou","monster","quest","help"}
TRUSTED_GOV = ("gov.in","nic.in","gov.uk","gov","gov.au","uidai.gov.in","incometax.gov.in","rbi.org.in")
LOOK_WORDS = r"(?:update|verify|verification|refund|claim|reward|redeliver\w*|login|kyc|secure|unlock|reactivat\w*|tracking|pay|bill|challan|fine|notice|helpdesk|support|cashback|lottery|prize|customs|approve\w*|restore|account|confirm)"

def hosts(t):
    out = []
    for m in HOST_RE.finditer(t):
        h = m.group(1)
        if re.fullmatch(r"(?:e\.g|i\.e|a\.m|p\.m|t\.c|u\.s|w\.r\.t)", h): continue
        if re.fullmatch(r"\d+(?:\.\d+)+", h): continue
        out.append(h)
    return out

def lookalike_link(t):
    brand = re.search(globals()['AUTH'], t)
    for h in hosts(t):
        tld = h.rsplit(".", 1)[-1]
        if h.endswith(TRUSTED_GOV): continue
        first = h.split(".")[0]
        if (tld in SUS_TLD and (re.search(LOOK_WORDS, h) or "-" in h or brand)) or ("-" in first and re.search(LOOK_WORDS, first)):
            return True
    return False

def mobile10(t): return re.search(r"(?<!\d)[6-9]\d{9}(?!\d)|\+91[\s-]?[6-9]\d{9}|x{7,}", t)
TOLLFREE = re.compile(r"\b1800[\s-]?\d|\b1860[\s-]?\d|toll[\s-]?free|\bnet ?banking|official (?:app|website)|\bbranch\b|visit (?:your )?(?:nearest )?branch|app khol|open the (?:\w+ )?app|via (?:the )?(?:official )?app|my account")

STRONG_THREAT = (r"(?:block\w*|lock\w*|disabled?|put on hold|suspend\w*|freez\w*|frozen|deactivat\w*|disconnect\w*|arrest\w*|legal action|penalty|seiz\w*|terminat\w*|"
                 r"warrant|banned?|\bhold\b|expire[sd]?\b.{0,25}(?:account|kyc|card|sim|number|service|connection|wallet|plan)|"
                 r"(?:account|kyc|card|sim|number|service|connection|wallet)\b.{0,25}expire[sd]?|cancel\w*.{0,15}(?:account|card|sim)|"
                 r"band ho\w*|kaat\w*|काट\w*|बंद|ब्लॉक|सीज|फ्रीज)")
AUTH = (r"(?:\b(?:sbi|hdfc|icici|axis|pnb|kotak|canara|baroda|yono|paytm|phonepe|gpay|bhim|upi|rbi|uidai|aadhaar|aadhar|income tax|trai|"
        r"police|cbi|customs|electricity|bijli|bsnl|jio|airtel|vodafone|vi|india post|fedex|dhl|amazon|flipkart|delhivery|dtdc|bluedart|"
        r"irctc|epfo|bank|banking|kyc|challan|sim|hmrc|dvla|halifax|nedbank|lloyds|barclays|natwest|santander|paypal|netflix)\b|बैंक|पुलिस|बिजली|आधार|पैन|केवाईसी|चालान)")

def imperson_strict(t):
    return bool(re.search(AUTH, t) and re.search(STRONG_THREAT, t) and re.search(rf"(?:{URL}|{PHONE}|\b(?:click|tap|call|contact|verify|update|submit|install|download|link|reply|complete|asap|immediately|urgently|karo|kijiye|kar do)\b|लिंक|संपर्क)", t))

# ------------------------------------------------------------------ extended scam families (all return truthy on lowercase text)
def _advance_pay(t):
    if re.search(r"\b(?:registration|processing|clearance|release|activation|insurance|handling)\s*(?:service\s*tax|servicestax|gst|fee|fees|charges?)\b", t) and re.search(r"\b(?:pay|send|deposit|transfer|remit|dena|dijiye|dedo|de do|jama)\b", t):
        return True
    return bool(re.search(r"\b(?:send|pay|deposit|transfer)\s+(?:a\s+)?(?:small\s+)?(?:rs\.?|₹|\$|£|usd|inr)?\s?\d[\d,]*\b.{0,60}(?:to claim|to receive|to release|to unlock|for (?:job|exclusive|registration|training|starter|processing|clearance|activation|delivery of)|starter kit)", t))

def _income_lure(t):
    return bool(re.search(r"\b(?:earn|make|get|income|salary|pay)\b.{0,50}(?:per day|a day|daily|every day|/ ?day|per hour|an hour|per week|a week|per month|a month)", t)
                and re.search(r"\b(?:job|application|selected|approve\w*|select\w*|work|task|recruit\w*|part[- ]?time|full[- ]?time|home|online|review|like|subscribe|data entry|hiring)\b", t)
                and re.search(r"(?:wa\.me|whatsapp|whats ?app|telegram|t\.me|\badd\b|\bjoin\b|http|www\.|\blink\b|\breply\b|\bregister\b)", t)
                and not re.search(r"\bcashback\b", t))

def _gov_link(t):
    if not re.search(r"\b(?:hmrc|hm revenue|dvla|income tax|irs|nhs|epfo|uidai|npci|council tax|tax refund|census|e-?filing|itr)\b", t): return False
    if not re.search(r"\b(?:refund|owe|owed|pending|payment|fine|penalty|claim|overpay\w*|entitled|due|redeem)\b", t): return False
    hs = [h for h in hosts(t) if not h.endswith(TRUSTED_GOV)]
    return bool(hs) or bool(re.search(r"https?://\d+\.\d+\.\d+\.\d+", t))

def _phish_verify(t):
    return bool(re.search(AUTH, t)
                and re.search(r"\b(?:verify|confirm|restore|reactivat\w*|unlock|validate|secure|log ?in|sign in|re-?enter)\b", t)
                and re.search(r"\b(?:account|device|card|access|identity|details|wallet|netbanking|online banking|profile|login|password)\b", t)
                and re.search(r"\b(?:not (?:you|done by you|authori[sz]ed)|unusual|suspicious|limit\w*|suspend\w*|block\w*|new device|unauthori[sz]ed|locked|restricted|deactivat\w*|failed|unable)\b", t)
                and re.search(URL, t))

def _prize_claim(t):
    win = re.search(r"\b(?:you(?:'ve| have| 've)?\s+(?:won|win)(?!'t|n't)|(?:u|you)\s+(?:have\s+)?(?:been\s+)?(?:selected|chosen)|collect your (?:winning|prize|gift|reward)|your (?:winning|prize)\b|you(?:'re| are) (?:a |the )?(?:lucky )?winner|your mobile number won|number (?:has )?won|congratulations?.{0,50}\b(?:won|win|gift|prize|reward)\b)", t)
    win = win or re.search(r"(?:बधाई.{0,80}(?:जीत|इनाम|लॉटरी)|आपने जीता|badhai ho.{0,60}(?:inaam|lottery|lakh)|inaam.{0,30}(?:laga|mila)|lottery.{0,30}\b(?:jeeta|jeete|jeeti|jita|mila|laga)\b|aapne.{0,40}\b(?:jeeta|jeete|jeeti)\b)", t)
    return bool(win and re.search(rf"(?:{URL}|{PHONE}|\b(?:call|txt|text|reply|claim|collect|pay|send|contact)\b|क्लेम|संपर्क)", t))

def _warranty(t): return bool(re.search(r"warranty.{0,50}\b(?:expir\w*|have now expire)", t) and re.search(r"\b(?:call|payment|rebate|renew)\b", t))
def _remote(t): return bool(re.search(r"\b(?:anydesk|teamviewer|quicksupport|rustdesk|screen ?shar\w*)\b", t))
def _crypto(t):
    return bool(re.search(r"\b(?:crypto\w*|bitcoin|forex|binary options?|trading signals?|guaranteed (?:profit|returns?)|assured returns?|double your (?:money|investment))\b|\b\d+% (?:daily|weekly) (?:returns?|profit)\b", t)
                and re.search(r"\b(?:whatsapp|telegram|join|register|wa\.me|t\.me|invest\w*|start now|software|spot)\b", t) and re.search(r"\b(?:earn|profit|income|returns?|make|daily|guaranteed|\d+ ?(?:hour|hr))\b", t))
def _customs_link(t): return bool(re.search(r"\b(?:customs|duty|clearance)\s*(?:charges?|fees?|payment|duty)\b", t) and re.search(URL, t))
def _points_cash(t): return bool(re.search(r"\b(?:reward )?points\b.{0,60}\b(?:expire|worth)\b.{0,80}\b(?:cash|redeem|convert)\b", t) and re.search(URL, t))
def _txn_callback(t):
    return bool(re.search(r"\b(?:debited|deducted|charged|transaction|used|attempt\w*)\b.{0,90}\b(?:not (?:done|made|authori[sz]ed|you)|if not you|did not|unauthori[sz]ed|if this (?:was )?not|if this be not)\b.{0,80}\b(?:call|contact|click|reply)\b", t)
                and (re.search(URL, t) or mobile10(t)) and not TOLLFREE.search(t))
def _upi_pin(t): return bool(re.search(r"(?:collect request|upi pin|यूपीआई पिन|कलेक्ट रिक्वेस्ट)", t) and re.search(r"(?:accept|enter|दर्ज|स्वीकार|approve)", t))
def _hi_notice(t):
    return bool(re.search(r"(?:पार्सल|चालान|बिजली|खाता|केवाईसी|बैंक|वाहन|कनेक्शन)", t) and re.search(r"(?:रोक|सीज|काट|ब्लॉक|बंद|फ्रीज|समन|एफआईआर|जब्त|जुर्माना)", t)
                and re.search(rf"(?:{URL}|{PHONE}|एपीके|apk|लिंक|संपर्क)", t))
AUTHORITY_CLAIM = (r"\b(?:police|cyber ?cell|cyber ?crime|crime branch|cbi|law enforcement|national cyber|inspector|acp|narcotics|enforcement directorate|"
                   r"customs|special investigation team|police headquarters|income tax|trai|court)\b")
ACCUSATION = (r"\b(?:suspect|illegal|criminal|complaint|investigation|misuse\w*|fake sim|sim issue\w*|morphed|obscene|pornographic|asleel|objectionable|"
              r"cyber fraud|digital fraud|financial fraud|money laundering|case register\w*|identity verify|linked account|suspicious activity)\b")
PRESSURE_MONEY = r"(?:\b(?:fee|fees|charges?|deposit|transfer|payment|pay|bhej\w*|jama|dena hoga|dijiye|rupe\w*|otp|pin|password|cvv|aadhaar number|card number|account number|bank details)\b|₹|\brs\.?\s?\d)"
PRESSURE_THREAT = r"\b(?:arrest\w*|fir (?:ho chuki|darj|hogi|lag\w*)|jail|warrant|digital arrest|legal action|seiz\w*|freez\w*|frozen|deactivat\w*|block\w*|suspend\w*|disconnect\w*)\b"
PRESSURE_ACT = r"\b(?:turant|abhi|immediately|urgent|jaldi|call karo|call kijiye|video call|do not tell|kisi ko mat|mat batana|link par|click|install|download|sampark)\b"
WARNING_WORDS = r"\b(?:beware|scam alert|be aware|advisory|never|do not|don'?t|aware|caution|stay alert|fraudsters|scammers)\b"
def coercive_authority(t):
    """authority claim (or accusation) PLUS pressure. Authority-only or accusation-only text is not enough."""
    if re.search(WARNING_WORDS, t): return False
    auth, acc = re.search(AUTHORITY_CLAIM, t), re.search(ACCUSATION, t)
    pressure = re.search(PRESSURE_MONEY, t) or re.search(PRESSURE_THREAT, t) or re.search(PRESSURE_ACT, t)
    return bool(auth and pressure)

def _digital_arrest(t):
    if re.search(WARNING_WORDS, t): return False
    directed = re.search(r"\b(?:aapko|aap|tum|you)\b.{0,30}\bdigital arrest\b|\bdigital arrest (?:ho|mein|me|kar)", t)
    return bool(directed or (re.search(AUTHORITY_CLAIM, t) and re.search(ACCUSATION, t) and coercive_authority(t)))
def _hi_authority_call(t): return bool(re.search(r"\b(?:cyber ?cell|crime branch|cbi|police)\b.{0,40}\b(?:se bol|bol raha|bol rahi|s bat kar|se baat)\b", t) and coercive_authority(t))

EXT_RULES = {
    "lookalike_link": lookalike_link, "advance_pay": _advance_pay, "income_lure": _income_lure, "gov_link": _gov_link,
    "phish_verify": _phish_verify, "prize_claim": _prize_claim, "warranty_call": _warranty, "remote_access": _remote,
    "crypto_income": _crypto, "customs_link": _customs_link, "points_to_cash": _points_cash, "txn_callback": _txn_callback,
    "upi_pin": _upi_pin, "hi_notice": _hi_notice, "digital_arrest": _digital_arrest, "authority_call_hi": _hi_authority_call,
}
HIGH_CONF = {"cred","fee","apk","prize","prize_claim","advance_pay","digital_arrest","authority_call","authority_call_hi","upi_pin","lookalike_link","remote_access","customs_link","points_to_cash"}


def _not_you_link(t):
    return bool(re.search(AUTH, t) and re.search(r"\b(?:if this (?:was|be|is) not (?:you|done by you)|if this be not|someone have log in|someone has logged|unknown device|new device|new payee|unregistered payee|unauthori[sz]ed (?:transaction|access|login)|suspicious activity|security check)\b", t)
                and re.search(URL, t) and not TOLLFREE.search(t))
def _subdomain_trick(t): return bool(re.search(r"(?:[a-z0-9-]+\.(?:com|gov|org|net|co)\.[a-z0-9-]+\.[a-z]{2,})|(?:\.gov\.uk\.[a-z])|(?:\.gov\.in\.[a-z])", t))
def _parcel_pay(t): return bool(re.search(r"\b(?:package|parcel|delivery|shipment)\b", t) and re.search(r"\b(?:confirm|pay)\b.{0,25}\b(?:payment|fee|charge)\b|\bconfirm the payment\b", t) and re.search(URL, t))
def _electricity_tonight(t): return bool(re.search(r"\belectricity\b.{0,40}\b(?:disconnect\w*|disconected|cut)\b.{0,40}\b(?:tonight|9\.?30)", t))
def _service_disable_link(t): return bool(re.search(AUTH, t) and re.search(r"\b(?:disabled?|deactivated?|terminated|locked?|suspended)\b", t) and re.search(r"\b(?:log ?on|log ?in|accept|verify|unlock|restore|follow the procedure)\b", t) and re.search(URL, t))
def _fx_profit(t): return bool(re.search(r"\b(?:invest\w*)\b.{0,60}\b(?:profit|return)\b.{0,40}\b(?:within|in)\b.{0,12}\b(?:\d+|xx|x)\s*(?:day|days|hr|hour)", t) and re.search(r"(?:wa\.link|wa\.me|whatsapp|call me|contact|telegram)", t))
def _job_letter(t): return bool(re.search(r"\b(?:interview letter|offer letter|admit card|job offer)\b", t) and re.search(URL, t) and (_subdomain_trick(t) or lookalike_link(t)))
def _malicious_label(t): return "sample of malicious sms" in t

EXT_RULES.update({"not_you_link": _not_you_link, "subdomain_trick": _subdomain_trick, "parcel_pay": _parcel_pay,
                  "electricity_tonight": _electricity_tonight, "service_disable_link": _service_disable_link,
                  "fx_profit": _fx_profit, "job_letter_link": _job_letter, "labelled_malicious": _malicious_label})
HIGH_CONF |= {"electricity_tonight","subdomain_trick","not_you_link","parcel_pay","service_disable_link"}


def _account_action_link(t):
    return bool(re.search(r"\b(?:update|verify|confirm|review|authenticat\w*|re-?activate|restore|log ?in|sign ?in)\b.{0,45}\b(?:account|profile|identity|payment|billing|details|database)\b", t)
                and re.search(r"\b(?:avoid|suspension|suspended|termination|cancel\w*|expir\w*|closure|restrict\w*|limit\w*|terminat\w*|urgent|on hold|hold)\b", t) and re.search(URL, t) and not official_links_only(t))
def _account_expire_login(t):
    return bool(re.search(r"\baccount\b.{0,70}\b(?:expir\w*|suspend\w*|on hold|clos\w*|lock\w*)\b.{0,70}\b(?:log ?in|sign ?in|click|visit|update|verify)\b", t) and re.search(URL, t) and not official_links_only(t))
EXT_RULES["account_expire_login"] = _account_expire_login
def _parcel_settlement(t): return bool(re.search(r"\b(?:parcel|package|delivery)\b", t) and re.search(r"\b(?:settlement|re-?\s?delivery|redelivery|missed-delivery|we miss(?:ed)? you)\b", t) and re.search(URL, t))
def _refund_form(t): return bool(re.search(r"\brefund\b.{0,70}\b(?:fill|submit|form|click|verify)\b", t) and (re.search(URL, t) or "below form" in t))
def _advance_fee_419(t): return bool(re.search(r"\b(?:transfer|million|\d+(?:\.\d+)?m\b|dollars?)\b.{0,90}\b(?:charity|inheritance|beneficiary|next of kin|business proposal|foreign base|urgent business)\b", t) and re.search(r"\b(?:email|contact|reply)\b", t))
def _wallet_credit_join(t): return bool(re.search(r"\b(?:credited|received)\b.{0,60}\b(?:wallet|account)\b.{0,60}\b(?:join|withdraw\w*|claim|register|click)\b", t) and re.search(URL, t))
def _stock_tip_group(t): return bool(re.search(r"\b(?:shares?|stocks?|intraday|nifty|banknifty|multibagger|lower circuit|upper circuit|tgt|target)\b", t) and re.search(r"\b(?:telegram|whatsapp|t\.me|wa\.me|join us)\b", t) and re.search(r"\b(?:loss|recover|profit|tips?|calls?|guaranteed|sure shot)\b", t))
def _confirm_payment_link(t): return bool(re.search(r"\bconfirm payment\b", t) and re.search(URL, t))
def _eligible_free_gift(t): return bool(re.search(r"congratulations?.{0,40}\b(?:eligible|selected|chosen)\b.{0,70}\b(?:free|gift|note|reward|prize|voucher)\b", t) and re.search(URL, t))
def _login_code_callback(t): return bool(re.search(r"\b(?:login|verification|otp)\b.{0,25}\bcode\b.{0,60}\bif you (?:do not|did not|didn'?t) (?:ask|request|initiate)\b", t) and re.search(URL, t))
EXT_RULES.update({"account_action_link": _account_action_link, "parcel_settlement": _parcel_settlement, "refund_form": _refund_form,
                  "advance_fee_419": _advance_fee_419, "wallet_credit_join": _wallet_credit_join, "stock_tip_group": _stock_tip_group,
                  "confirm_payment_link": _confirm_payment_link, "eligible_free_gift": _eligible_free_gift, "login_code_callback": _login_code_callback})
HIGH_CONF |= {"account_action_link","parcel_settlement","advance_fee_419","stock_tip_group","login_code_callback"}

# ------------------------------------------------------------------ legitimate evidence
ASK = r"\b(?:call|click|tap|visit|reply|contact|verify|update|confirm|submit|pay|share|send|enter|login|log in)\b"
def _otp_delivery(t):
    code = (re.search(r"\b(?:otp|one[- ]time (?:password|passcode|pin)|verification code|security code|passcode|login code|code|password)\b.{0,50}\b(?:is|be|:|are)\s*[`'\"]*\s*(?:g-)?(?:\d{4,8}|x{4,8})\b", t)
            or re.search(r"(?:^|\s)(?:g-)?(?:\d{4,8}|x{4,8})\s+(?:is|be)\s+your\b.{0,40}\b(?:code|otp|passcode|password)\b", t)
            or re.search(r"\b(?:otp|code)\b.{0,15}(?:\d{4,8}|x{4,8})\b.{0,60}\b(?:valid|expires?|do not share|don'?t share)\b", t))
    if not code or re.search(r"\b(?:call|click|tap|visit|reply|contact)\b|http|www\.", t): return False
    from .triage_rules import _NEG_SHARE, _NEG_HI
    rest = _NEG_HI.sub(" ", _NEG_SHARE.sub(" ", t))                       # drop 'do not share ...' clauses first
    return not re.search(r"\b(?:kyc|block\w*|last chance|reward|redeem|renew\w*|bank manager|asap|tell|give|send|share|sanga|ivvandi|batao|bata|bhejo|expiry date|limit)\b", rest)
def _txn_alert(t):
    if re.search(DEV_CUT, t): return False
    if re.search(r"\b(?:disconnect\w*|power cut|cut (?:ho|हो)|कट जाएगी|बिजली कट|shut ?down|shut off|install|jaldi|warna|no time)\b", t): return False
    return bool(re.search(r"\b(?:debited|credited|withdrawn|deposited|received|payment (?:of|received|successful|has been)|recharge (?:of )?.{0,40}successful|auto-?debited|bill .{0,40}(?:paid|payment))\b", t)
                and re.search(r"(?:rs\.?\s?\d|₹\s?\d|inr\s?\d|\d[\d,]*\.\d\d|\bamount\b)", t)
                and re.search(r"\b(?:a/c|account|upi|wallet|balance|ref|txn|transaction|utr|bank|card|recharge|bill|emi)\b", t)
                and not re.search(URL, t) and not re.search(r"\b(?:click|verify|update|confirm|submit|login)\b", t)
                and (not mobile10(t) or TOLLFREE.search(t)))
def _order_status(t):
    return bool(re.search(r"\b(?:order|shipment|package|parcel|delivery|awb|tracking|booking)\b.{0,90}\b(?:shipped|dispatched|delivered|out for delivery|arriv\w*|reached|packed|confirmed|placed|on its way|will get to you|booked)\b", t)
                and not re.search(r"\b(?:incomplete|failed|held|stuck|customs|redeliver\w*|reschedule|pay\b|fee|verify|confirm your address|update (?:your )?address)\b", t))
def _warning(t):
    return bool(re.search(r"\b(?:beware|scammers?|fraudsters?|phishing|stay alert|never share|do not (?:click|share)|don'?t click|will never ask|be aware|caution|unsolicited tips?)\b", t)
                and not re.search(r"\b(?:click here|verify now|log ?in now|update now|claim)\b", t))
def _service_notice(t):
    if re.search(DEV_CUT, t): return False
    if re.search(r"\b(?:disconnect\w*|power cut|cut (?:ho|हो)|कट जाएगी|बिजली कट|shut ?down|shut off|lights on)\b", t): return False
    return bool(re.search(r"\b(?:appointment|reminder|renewal|due (?:on|date)|will expire (?:tomorrow|on)|your (?:plan|pack|subscription|membership)|booking (?:confirmed|id)|ticket|pnr|invoice|statement is ready|thank you for|support ticket|reference no)\b", t)
                and not re.search(RISK_PROMO, t) and not re.search(rf"(?:{URL}).{{0,60}}\b(?:verify|confirm|update|pay)\b", t))

COMM = re.compile(r"\b(?:offers?|sale|off|discounts?|cashback|buy|shop|shopping|orders?|stores?|recharge|talk ?time|data|plans?|packs?|validity|subscri\w+|membership|download|app|t&c|tnc|t c|terms|opt ?out|unsub\w*|valid (?:till|until|for|on)|limited|launch\w*|bhk|flat|emi|book\w*|coupon|code|promo\w*|free|deals?|grab|hurry|upto|up to|bonus|vouchers?|delivery|menu|festival|diwali|holi|dhamaka|collection|brand|fest|mrp|rs\.?|₹|lacs?|lakh|price|only at|dial|call to|visit|enjoy|save|special|exclusive|new arrival|launch|property|apartments?|sq ?ft|possession|gold|jewel\w*|restaurant|salon|spa|hotel|holiday|packages?|flight|ride|cab)\b")
RISK_PROMO = (r"\b(?:otp|pin|cvv|password|passcode|verify|verification|kyc|suspend\w*|blocked|frozen|refund|prize|winner|won|lottery|lucky draw|jackpot|selected|"
              r"guaranteed|assured returns?|crypto\w*|bitcoin|forex|arrest|police|court|legal action|penalty|customs|parcel|courier|incomplete address|aadhaar|pan card|"
              r"work from home|part[- ]?time|earn \w+ (?:per|a) day|registration fee|processing fee|account (?:no|number)|investment|invest|tip|target|tgt|stoploss|multibagger|"
              r"unsolicited|loan|credit score|cibil|disbursement|approved|eligib\w+|rebate|warranty|gift card|you have won|congratulations?|collect your|"
              r"temporar\w+|limit\w* access|restricted|locked|on hold|unusual activity)\b")
def _promo(t):
    n = len({m.group(0) for m in COMM.finditer(t)})
    return n >= 2 and not re.search(RISK_PROMO, t)


RISK_BROAD = re.compile(r"\b(?:otp|pin|cvv|password|passcode|verify|verification|kyc|suspend\w*|blocked?|frozen|freez\w*|refund|prize|winner|won|lottery|jackpot|selected|guaranteed|assured|crypto\w*|bitcoin|forex|invest\w*|profit|arrest|police|court|legal|penalty|customs|aadhaar|pan card|work from home|part[- ]?time|earn|salary|loan|credit card|credit score|cibil|account|a/c|bank|card|upi|wallet|payment|pay|deposit|transfer|urgent|immediately|expire[sd]?|deactivat\w*|disconnect\w*|unlock|restore|login|log in|click|link|http|www|call|dial|contact|reply|text|txt|send|claim|win|free entry|adult|sex\w*|dating|girls?|massage|bikini|date site|hook ?up|escort|slutty\w*|sluttyladi|female members?|sizzling|nude|nsfw|lover|meetforfun|models)\b|\d{9,}")
def _operator_content(t): return bool(re.search(r"jazzmobilemag|for (?:pictures|details|quick recipe),? click (?:the |this )?(?:free )?(?:video )?link", t))
def _public_info(t): return bool(re.search(r"\b(?:ebola|covid|vaccine|symptoms?|preventive|health(?:y)?|flu|lifestyle|immune)\b", t) and not re.search(r"\b(?:invest|earn|loan|win)\b", t))
def _chat_like(t):
    return len(t) >= 15 and not RISK_BROAD.search(t) and not re.search(r"\d{5,}", t)
def _ussd_offer(t): return bool(re.search(r"\*\d{2,4}(?:\*\d+)*#|\bdial\b", t) and re.search(r"\b(?:data|minutes?|talk ?time|gb|mb|balance|pack|validity|recharge|offer|sms)\b", t) and not RISK_PROMO_SHORT.search(t))
RISK_PROMO_SHORT = re.compile(r"\b(?:otp|pin|cvv|password|verify|kyc|suspend\w*|blocked|refund|prize|winner|won|lottery|jackpot|loan|police|arrest)\b")

#__LEGIT_RULES_BASE__
LEGIT_RULES = (("otp_delivery", _otp_delivery, "high"), ("txn_alert", _txn_alert, "high"), ("order_status", _order_status, "medium"),
               ("advisory_warning", _warning, "high"), ("service_notice", _service_notice, "medium"), ("promo", _promo, "medium"),
               ("operator_content", _operator_content, "medium"), ("public_info", _public_info, "medium"), ("ussd_offer", _ussd_offer, "medium"), ("chat_like_no_risk", _chat_like, "low"))


WIN_PHRASE = re.compile(r"\b(?:you(?:'ve| have)?\s+won|you(?:'re| are) (?:a |the )?(?:lucky )?winner|winner of|has won|have won|selected|awarded|won (?:a|rs|£|\$|₹)|your (?:winning|prize)|inaam|you win|u win|u have won)\b|बधाई|जीत")
PREMIUM_SMS = re.compile(r"\b(?:txt|text|send|sms|reply)\b.{0,40}\bto\s+\d{4,6}\b")
def weak_hit_guard(only, t, source_kind):
    """downgrade lone, easily-confused signals to review"""
    if only <= {"prize", "prize_claim"} and not WIN_PHRASE.search(t):
        return "promo/contest wording without a win statement"
    if only == {"cred"} and (re.search(r"\b(?:incorrect|invalid|retry|re-?enter|not you|did ?n'?t request|if you did not|reset your)\b", t) or PREMIUM_SMS.search(t)):
        return "credential word in a form-error / reset / premium-SMS context"
    if "lookalike_link" in only and re.search(r"\b(?:single (?:lady|girl)|hot girls?|dating|meet (?:local|singles)|sexy|xxx|adult)\b", t) and len(only) == 1:
        return "adult/dating spam rather than fraud"
    return None


def _generic_account_threat(t):
    """brand-less 'your account/card/wallet is locked/closed ... login/click/call' (Nigerian/Indian/UK variants)"""
    return bool(re.search(r"\byour\b.{0,25}\b(?:account|a/?c|acct|atm card|debit card|card|wallet|online)\b.{0,40}\b(?:lock\w*|block\w*|clos\w*|suspend\w*|deactivat\w*|disabled?|limit\w*)\b|\b(?:account|a/?c|acct|atm card|wallet)\b.{0,25}\b(?:has|have|had|have been|has been|been|will be)\b.{0,12}\b(?:lock\w*|block\w*|clos\w*|suspend\w*|deactivat\w*)\b", t)
                and re.search(rf"(?:{URL}|{PHONE}|(?<!\d)\d{{6,8}}(?!\d)|\b(?:click|login|log in|call|contact|press|reactivat\w*|re_activate|unlock\w*|update)\b)", t)
                and not TOLLFREE.search(t) and not re.search(r"\bas per your request\b|\byou (?:requested|asked)\b", t))
def _handling_prize(t): return bool(re.search(r"\b(?:u|you)\s*(?:hv|have|'ve)?\s*won\b", t) and re.search(r"\b(?:handling|delivery|courier|shipping|processing)\s*(?:charges?|fees?)\b|\bpay\b", t))
def _courier_accept_link(t): return bool(re.search(r"\b(?:courier|parcel|package)\b.{0,40}\b(?:send out|sent|dispatched|arrived|waiting)\b.{0,40}\b(?:check|accept|track|confirm|open)\b", t) and re.search(URL, t))
def _update_info_link(t): return bool(re.search(r"\b(?:update|verify|confirm)\s+(?:your\s+)?(?:account|login|personal|bank)\s+(?:information|info|details)\b", t) and re.search(URL, t))
def _stock_pump(t): return bool(re.search(r"\b(?:explosive pick|strong-?buy|up over \d+%|hot stock tip|penny stock|nasdaq symbol|insider tip)\b", t))
EXT_RULES.update({"generic_account_threat": _generic_account_threat, "handling_prize": _handling_prize, "courier_accept_link": _courier_accept_link,
                  "update_info_link": _update_info_link, "stock_pump": _stock_pump})
HIGH_CONF |= {"generic_account_threat","handling_prize","update_info_link","stock_pump"}
def _vaccination(t): return bool(re.search(r"\b(?:successfully (?:be )?vaccinat\w+|vaccination certificate|covishield|covaxin)\b", t) and not re.search(r"\b(?:pay|fee|otp)\b", t))
def _service_closure(t): return bool(re.search(r"\b(?:closed successfully|has been closed|been resolved|request no|complaint no|service request)\b", t) and not re.search(URL, t))
def _vas_quiz(t): return bool(re.search(r"(?:\^1/2|\b1\)\s*\w+.{0,60}2\)\s*\w+)", t) and re.search(r"\b(?:reply|sms|send)\b", t))
def _exam_result_service(t): return bool(re.search(r"\b(?:result|admit card|selection)\b.{0,60}\b(?:send|sms|short code|index number)\b", t) and not re.search(URL, t))
LEGIT_RULES = LEGIT_RULES[:-1] + (("vaccination", _vaccination, "medium"), ("service_closure", _service_closure, "medium"),
                                  ("vas_quiz", _vas_quiz, "low"), ("exam_result_service", _exam_result_service, "low")) + LEGIT_RULES[-1:]


def _seed_phrase(t): return bool(re.search(r"\b(?:12|24|twelve)[- ]?words?\b|\bprivate key\b|\bseed phrase\b|\brecovery phrase\b", t) and re.search(r"\b(?:verify|restore|secure|enter|submit|validate|visit)\b", t))
def _apple_locked(t): return bool(re.search(r"\b(?:apple id|icloud|google account|microsoft account)\b.{0,60}\b(?:lock\w*|disabled|suspend\w*|unauthori[sz]ed)\b", t))
def _unusual_login_visit(t): return bool(re.search(r"\b(?:unusual|suspicious|unauthori[sz]ed)\b.{0,40}\b(?:login|sign[- ]?in|attempt|activity)\b", t) and re.search(r"\b(?:visit|go to|open|click)\b\s+\S*[a-z0-9-]+\.[a-z0-9.-]+", t))
def _hiring_lure(t): return bool(re.search(r"\b(?:hiring manager|project manager|recruit\w*|hr manager)\b", t) and re.search(r"\b(?:lucrative|earn|salary|income)\b", t) and not re.search(r"\bresume\b", t))
def _yojana_credit(t): return bool(re.search(r"\b(?:yojana|scheme|subsidy)\b", t) and re.search(r"\b(?:credit\w*|deposit\w*)\b", t) and re.search(URL, t))
def _account_credit_enter(t): return bool(re.search(r"\b(?:a/?c|account)\b.{0,12}\bcan be credit\w*\b", t) and re.search(r"\b(?:enter|sign up|check now|fill)\b", t) and re.search(URL, t))
EXT_RULES.update({"seed_phrase": _seed_phrase, "apple_locked": _apple_locked, "unusual_login_visit": _unusual_login_visit,
                  "hiring_lure": _hiring_lure, "yojana_credit": _yojana_credit, "account_credit_enter": _account_credit_enter})
HIGH_CONF |= {"seed_phrase","apple_locked","unusual_login_visit"}


def _fund_419(t): return bool(re.search(r"\b(?:business|fund|funds|deposit|transfer|inheritance|contract)\b.{0,50}\b\d+(?:\.\d+)?\s*(?:million|m\b)", t) and re.search(r"\b(?:reply|email|contact|trust you)\b", t))
def _etoll(t): return bool(re.search(r"\be-?toll\b|\be-?tag\b|\btoll (?:fee|payment)\b", t) and re.search(r"\b(?:failed|unpaid|pending|due|undetected)\b", t) and re.search(r"\bpay\b", t))
def _car_wrap(t): return bool(re.search(r"\b(?:decal|sticker|advert|wrap|logo)\b.{0,60}\b(?:car|truck|vehicle)\b.{0,80}\b(?:weekly|get \$?x+|earn|paid|interested)\b", t))
def _select_prize(t): return bool(re.search(r"\byou (?:have )?(?:select|selected|won|win)\b.{0,30}\bprize\b", t))
def _late_bill_link(t): return bool(re.search(r"\b(?:payment|bill)\b.{0,50}\b(?:could not be process\w*|failed|declined)\b.{0,80}\bupdate\b.{0,30}\b(?:payment|billing)\b", t) and re.search(URL, t))
def _device_registered(t): return bool(re.search(r"\bnew (?:mobile )?device\b.{0,60}\bregister\w*\b.{0,80}\bif this be not you\b", t))
EXT_RULES.update({"fund_419": _fund_419, "etoll": _etoll, "car_wrap": _car_wrap, "select_prize": _select_prize,
                  "late_bill_link": _late_bill_link, "device_registered": _device_registered})
HIGH_CONF |= {"fund_419","etoll","car_wrap","select_prize","late_bill_link"}

DEV_CUT = r"(?:cut\s*हो|कट\s*(?:जाएगी|हो)|बिजली\s*कट|कनेक्शन\s*कट)"
# ------------------------------------------------------------------ official domains / id-stripping / utility threats
OFFICIAL_DOMAINS = ("sbi.co.in","onlinesbi.com","onlinesbi.sbi","sbicard.com","hdfcbank.com","icicibank.com","axisbank.com","kotak.com","pnbindia.in",
    "bankofbaroda.in","canarabank.com","idfcfirstbank.com","yesbank.in","indusind.com","paytm.com","phonepe.com","amazon.in","amazon.com","amazonpay.in",
    "flipkart.com","myntra.com","swiggy.com","zomato.com","mahadiscom.in","bescom.org","tatapower.com","bsesdelhi.com","uidai.gov.in","incometax.gov.in",
    "epfindia.gov.in","irctc.co.in","indiapost.gov.in","jio.com","airtel.in","vi.in","bsnl.co.in","wipro.com","tcs.com","infosys.com","gov.in","nic.in",
    "google.com","microsoft.com","apple.com","netflix.com","hdfclife.com","licindia.in","npci.org.in","bhimupi.org.in","cowin.gov.in","sanchar-saathi.gov.in")
def official_links_only(t):
    hs = hosts(t)
    return bool(hs) and all(any(h == o or h.endswith("." + o) for o in OFFICIAL_DOMAINS) for h in hs)

ID_NUMBER = re.compile(r"(?:a/?c|acct|account|ref(?:erence)?|consumer|customer id|bill|order|txn|transaction|upi ref|utr|policy|reg(?:istration)?)\s*(?:no\.?|number|id|#|:)?\s*[:#-]?\s*[\w-]*\d{6,}[\w-]*", re.I)
def strip_ids(t): return ID_NUMBER.sub(" ", t)

def _utility_threat(t):
    return bool(re.search(r"(?:\b(?:electricity|bijli|power|connection|bill)\b|बिजली)", t) and (re.search(DEV_CUT, t) or re.search(r"\b(?:disconnect\w*|power cut|cut (?:ho|हो)|कट जाएगी|बिजली कट|shut ?down|shut off|kat\w*|connection cut|कनेक्शन कट)\b", t))
                and re.search(r"(?:tonight|today|immediately|jaldi|asap|abhi|\b\d{1,2}(?::\d\d)?\s?(?:pm|am|baje)\b|install|within \d+|no time|आज|तुरंत|अभी|बजे)", t)
                and re.search(r"(?:\b(?:pay|payment|app|install|clear|bhar\w*|kar do|karo)\b|ऐप|भुगतान|बकाया)", t))
EXT_RULES["utility_threat"] = _utility_threat
HIGH_CONF.add("utility_threat")
SOFT_WITH_OFFICIAL_LINK = {"imperson","phish_verify","points_to_cash","prize_claim","not_you_link","parcel","parcel_pay","parcel_settlement",
                           "account_action_link","service_disable_link","update_info_link","hi_notice","utility_threat","cred","refund_form"}

# ------------------------------------------------------------------ main decision (label policy v2)
# Policy v2 (project owner's decision): unsolicited promotion, bulk advertising and bulk job/loan ads are SCAM (spam group);
# genuine bank notifications, OTPs, delivery alerts and personal messages are LEGITIMATE; uncertain -> REVIEW.
# scam_category keeps ordinary spam (UNSOLICITED_PROMO, BULK_JOB_LOAN_AD) distinguishable from fraud for later analysis.
POLICY_VERSION = "v2"
SPAM_CATEGORIES = {"UNSOLICITED_PROMO", "BULK_JOB_LOAN_AD"}
LEGIT_SOURCE_PROMO = "review"   # a source-'legitimate' message with promotional content: 'unsolicited?' cannot be told from text -> review

def load_manual(path="data/interim/manual_decisions.csv"):
    p = Path(path)
    if not p.exists(): return {}
    m = pd.read_csv(p, keep_default_na=False)
    cat = m["category"] if "category" in m.columns else [""] * len(m)
    return {(r.source, r.source_id): (r.decision, r.reason, c) for r, c in zip(m.itertuples(), cat)}

SIGNAL_CAT = {"cred":"OTP_CREDENTIAL","fee":"ADVANCE_FEE","advance_pay":"ADVANCE_FEE","fund_419":"ADVANCE_FEE","prize":"LOTTERY_PRIZE","prize_claim":"LOTTERY_PRIZE",
  "handling_prize":"LOTTERY_PRIZE","select_prize":"LOTTERY_PRIZE","eligible_free_gift":"LOTTERY_PRIZE","authority_call":"DIGITAL_ARREST","digital_arrest":"DIGITAL_ARREST",
  "authority_call_hi":"DIGITAL_ARREST","family":"FAMILY_EMERGENCY","apk":"MALWARE_APK","remote_access":"REMOTE_ACCESS","job":"JOB_FRAUD","income_lure":"JOB_FRAUD",
  "hiring_lure":"JOB_FRAUD","job_letter_link":"JOB_FRAUD","parcel":"DELIVERY","parcel_pay":"DELIVERY","parcel_settlement":"DELIVERY","courier_accept_link":"DELIVERY",
  "customs_link":"DELIVERY","etoll":"TOLL_FEE","electricity_tonight":"UTILITY","crypto_income":"INVESTMENT","fx_profit":"INVESTMENT","stock_tip_group":"INVESTMENT",
  "stock_pump":"INVESTMENT","upi_pin":"UPI_PAYMENT","wallet_credit_join":"UPI_PAYMENT","confirm_payment_link":"UPI_PAYMENT","yojana_credit":"UPI_PAYMENT",
  "account_credit_enter":"LOAN_FRAUD","imperson":"IMPERSONATION","gov_link":"IMPERSONATION","hi_notice":"IMPERSONATION"}
CAT_PRIORITY = ["DIGITAL_ARREST","OTP_CREDENTIAL","ADVANCE_FEE","FAMILY_EMERGENCY","MALWARE_APK","LOTTERY_PRIZE","DELIVERY","UTILITY","TOLL_FEE","JOB_FRAUD",
                "INVESTMENT","UPI_PAYMENT","LOAN_FRAUD","REMOTE_ACCESS","IMPERSONATION","PHISHING"]

def category_from_hits(hits, t, src_cat="unassigned"):
    cats = {SIGNAL_CAT.get(h, "PHISHING") for h in hits}
    cat = next((c for c in CAT_PRIORITY if c in cats), None)
    if cat is None:
        return src_cat if src_cat not in ("unassigned", "none", "") else "OTHER_FRAUD"
    if cat in ("PHISHING", "IMPERSONATION", "OTP_CREDENTIAL"):
        if re.search(r"\bkyc\b|केवाईसी", t): return "KYC"
        if re.search(r"\b(?:bank|banking|upi|netbanking|sbi|hdfc|icici|axis|paytm|phonepe|card|account|a/c)\b|बैंक", t): return "BANKING"
    return cat

def hindi_category(t):
    """category for Devanagari lure / advert wording (read against all 60 unique messages of the 15k Hindi file); None = no match"""
    if not re.search(r"[\u0900-\u097F]", t): return None
    for pat, cat in [(r"केवाईसी", "KYC"), (r"बैंक\s*खाता|खाता\s*बंद", "BANKING"), (r"निवेश", "INVESTMENT"), (r"ऋण|लोन", "BULK_JOB_LOAN_AD"),
                     (r"पैसे\s*कमाने|कमाई\s*शुरू|घर\s*बैठे", "JOB_FRAUD"), (r"प्रतियोगिता", "UNSOLICITED_PROMO"), (r"कैशबैक", "UPI_PAYMENT"),
                     (r"पुरस्कार|इनाम|जीत|लॉटरी|बोनस|उपहार|वाउचर|रिवॉर्ड|चयन", "LOTTERY_PRIZE"),
                     (r"छूट|ऑफर|सेल|डील|सदस्यता|क्रेडिट\s*कार्ड|शॉपिंग", "UNSOLICITED_PROMO")]:
        if re.search(pat, t): return cat
    return None

PROMO_RULES = {"promo", "operator_content", "ussd_offer", "vas_quiz", "chat_like_no_risk"}
def _promo_any(t): return _promo(t) or _operator_content(t) or _ussd_offer(t) or _vas_quiz(t)

# ------------------------------------------------------------------ refinements after reading policy-v2 samples
STRONG_COMMERCIAL = re.compile(r"(?:%|₹|\brs\b\.?|\boffers?\b|\bsale\b|\bdiscounts?\b|\bcoupon\b|\bvouchers?\b|\bt&c\b|\btnc\b|\bvalid (?:till|until|for|on)\b|\bupto\b|\bup to\b|\bcashback\b|\bdial\b|\bmrp\b|\bbhk\b|\bemi\b|\bunsub\w*|\bstop to\b|\bpre-?approved\b|\bwalk-?in\b)")
CHAT_MARKERS = re.compile(r"\b(?:lol|haha+|lah|leh|lor|omg|bro|bhai|yaar|dun|wan|wat|abt|gonna|wanna|thx|plz|ur|u)\b|\bmera\b|\bmujhe\b|\bkya\b")
STATEMENT_CONTEXT = re.compile(r"\b(?:statement|invoice|due (?:on|date)|account ending|a/?c ending|balance|debited|credited|successful recharge|recharge (?:of|successful)|power bill|electricity bill|bill (?:of|due|payment)|emi (?:of|has been|debited|kat)|auto-?debit)\b")
def _promo(t):
    n = len({m.group(0) for m in COMM.finditer(t)})
    return bool(n >= 2 and STRONG_COMMERCIAL.search(t) and not re.search(RISK_PROMO, t) and not STATEMENT_CONTEXT.search(t)
                and not (CHAT_MARKERS.search(t) and n < 4))
AD_CUE = re.compile(r"\b(?:apply|offer|pre-?approved|eligible|instant|low interest|interest rate|walk-?in|hiring|vacanc\w+|salary|call now|no documents?|guarantor|limit|opening|interview|resume|placement|rate of interest|processing)\b")
def _loan_job_ad(t):
    return bool(re.search(r"\b(?:loans?|emi|credit card|hiring|vacanc\w+|recruit\w*|job openings?|walk[- ]?in|placements?|naukri|jobs?)\b", t) and AD_CUE.search(t)
                and not STATEMENT_CONTEXT.search(t) and not CHAT_MARKERS.search(t)
                and not re.search(r"\b(?:otp|pin|cvv|password|passcode|kyc|suspend\w*|blocked|frozen|arrest|police)\b", t))

BRAND_TOKENS = r"(?:netflix|amazon|paypal|apple|google|microsoft|sbi|hdfc|icici|axis|paytm|phonepe|jio|airtel|dhl|fedex|ups|usps|hmrc|dvla|halifax|lloyds|barclays|natwest|revolut|binance|coinbase|flipkart)"
def _brand_hyphen_host(t):
    for h in hosts(t):
        first = h.split(".")[0]
        if "-" in first and re.search(BRAND_TOKENS, first) and not any(h == o or h.endswith("." + o) for o in OFFICIAL_DOMAINS): return True
    return False
def _failed_delivery_link(t):
    return bool(re.search(r"\b(?:package|parcel)\b.{0,50}\b(?:fail\w*|missed|undeliver\w*|could not be delivered|unable to deliver)\b", t) and re.search(URL, t) and not official_links_only(t))
def _collection_prize(t):
    return bool(re.search(r"\b(?:await\w* collection|collect your|complimentary)\b.{0,70}\b(?:holiday|cash|prize|gift|reward|voucher)\b", t) and re.search(rf"(?:{URL}|{PHONE}|\b(?:call|txt|text)\b|\d{{5,}})", t))
EXT_RULES.update({"brand_hyphen_host": _brand_hyphen_host, "failed_delivery_link": _failed_delivery_link, "collection_prize": _collection_prize})
HIGH_CONF |= {"brand_hyphen_host", "failed_delivery_link", "collection_prize"}
SIGNAL_CAT.update({"brand_hyphen_host": "PHISHING", "failed_delivery_link": "DELIVERY", "collection_prize": "LOTTERY_PRIZE", "utility_threat": "UTILITY"})

def _out(lab, method, why, conf, sig="", cat=""):
    return lab, method, why, conf, sig, cat

def decide(source, source_id, text, source_kind, source_quality, original_label, manual, src_category="unassigned"):
    key = (source, source_id)
    t = normalise(str(text))
    hits = scam_hits(text)
    sig = ",".join(hits)
    if key in manual:
        lab, why, cat = manual[key]
        if lab == "scam" and not cat: cat = category_from_hits(hits, t, src_category) if hits else (hindi_category(t) or "UNSOLICITED_PROMO")
        return _out(lab, "manual_read", why, "high" if lab != "review" else "low", sig, cat if lab == "scam" else "")

    # ---- family decisions (read in bulk)
    if source == "kaggle_hindi_bundle" and source_kind != "legit":
        return _out("review", "family_review", "garbled machine translation of English spam; intent not reliably readable", "low", sig)
    if source in ("synthetic_tier_c", "indian_scam_synthetic") and source_kind == "fraud" and (hits or re.search(rf"(?:{URL}|{PHONE}|t\.me|wa\.me|\.apk)", t)):
        return _out("scam", "family_read", "synthetic fraud template with a concrete lure (phone, link, look-alike domain, APK, PIN or fee)", "high", sig,
                    category_from_hits(hits, t, src_category))
    if source == "ysangam_hinglish" and source_kind != "legit" and not hits:
        if coercive_authority(t):
            return _out("scam", "family_read", "authority claim + pressure (money, credentials, coercive consequence or instruction to act) in a call-script line", "medium", sig, "DIGITAL_ARREST")
        if re.search(AUTHORITY_CLAIM, t) or re.search(ACCUSATION, t) or re.search(r"\b(?:digital arrest|fir)\b", t):
            return _out("review", "family_review", "call-script fragment: authority claim or accusation only; no money, credential, threat or action requested", "low")

    # ---- fraud evidence
    if hits and official_links_only(t) and set(hits) <= SOFT_WITH_OFFICIAL_LINK and not re.search(r"\b(?:otp|pin|cvv|password|passcode)\b", t):
        hits = []                                  # the only link is the brand's real site: cannot be phishing via that link
    if hits:
        only = set(hits)
        urgent = re.search(r"\b(?:asap|immediately|urgently|turant|jaldi|abhi|tonight)\b", t)
        if only <= {"imperson"} and not urgent and (TOLLFREE.search(t) or not re.search(rf"(?:{URL}|{PHONE})", t)):
            return _out("review", "rule_conflict", "organisation + threat but only an official/toll-free contact; could be genuine notice", "low", sig)
        if source_kind == "legit" and only <= {"cred", "job", "family", "fee"}:
            return _out("review", "rule_conflict", "source says legitimate; only one weak scam signal (" + ",".join(sorted(only)) + ")", "low", sig)
        g = weak_hit_guard(only, t, source_kind)
        if g: return _out("review", "rule_conflict", "weak scam signal only: " + g, "low", sig)
        conf = "high" if (len(only) >= 2 or only & HIGH_CONF) else "medium"
        why = "scam evidence: " + ", ".join(sorted(only)) + (" (overrides source 'legitimate')" if source_kind == "legit" else "")
        return _out("scam", "rule_scam", why, conf, sig, category_from_hits(hits, t, src_category))

    # ---- genuine notifications / personal / service messages stay legitimate
    for name, fn, conf in LEGIT_RULES:
        if name in PROMO_RULES: continue
        if fn(t): return _out("legitimate", "rule_legit", f"{name}: genuine notification/service/advisory, no scam evidence", conf)

    # ---- policy v2: promotional / bulk-advert / bulk job-loan content
    loose_promo = source_kind in ("spam", "fraud") and bool(COMM.search(t)) and not STATEMENT_CONTEXT.search(t) and not RISK_PROMO_SHORT.search(t) \
                  and not (CHAT_MARKERS.search(t) and len(t.split()) < 25)
    cat = "BULK_JOB_LOAN_AD" if _loan_job_ad(t) else ("UNSOLICITED_PROMO" if (_promo_any(t) or loose_promo) else hindi_category(t))
    if cat:
        if source_kind in ("spam", "fraud"):
            return _out("scam", "rule_scam", "policy v2: unsolicited promotional / bulk advertising or bulk job-loan advert (source: spam)", "medium", sig, cat)
        if LEGIT_SOURCE_PROMO == "review":
            return _out("review", "rule_conflict", "promotional content but the source labelled it legitimate; solicited vs unsolicited unknown (policy v2)", "low", sig)

    if source_kind == "legit":
        return _out("legitimate", "source_label", "source says legitimate; no scam or promotional evidence found", "medium")
    return _out("review", "unresolved", "source says spam/fraud but no decisive fraud or promotional evidence in the text", "low")

def Adjudicate_frame(df):
    manual = load_manual()
    cat_src = df.scam_category if "scam_category" in df.columns else pd.Series("unassigned", index=df.index)
    res = [decide(s, sid, m, k, q, str(o), manual, c) for s, sid, m, k, q, o, c in
           zip(df.source, df.source_id, df.message, df.source_kind, df.source_quality, df.original_label, cat_src)]
    out = pd.DataFrame(res, columns=["final_label", "final_method", "final_reason", "final_confidence", "final_signals", "final_category"], index=df.index)
    out["final_category"] = out.final_category.where(out.final_label == "scam", out.final_label.map({"legitimate": "none", "review": "unassigned"}))
    out["scam_group"] = [("spam" if c in SPAM_CATEGORIES else "fraud") if l == "scam" else ("none" if l == "legitimate" else "unassigned")
                         for l, c in zip(out.final_label, out.final_category)]
    return out

def normalise(t):
    t = t.lower()
    t = re.sub(r"(?<=[a-z])0(?=[a-z])", "o", t)                      # bl0cked -> blocked
    t = re.sub(r"(?<=[a-z])-(?=[a-z]{2,}\b)", "-", t)
    t = re.sub(r"(?<=[a-z0-9])\s+-\s*(?=[a-z0-9])", "-", t)           # 'help -revolut.info' -> 'help-revolut.info'
    t = re.sub(r"(?<=[a-z0-9])-\s+(?=[a-z0-9]+\.[a-z]{2,})", "-", t)
    t = re.sub(r"\bb-lock", "block", t)
    t = re.sub(r"(?:\bipat'?ym|\bpatym|\bpytm|pay2tm|\bp\.?a\.?t\.?m\b|\bpay\s+tm)", "paytm ", t)
    t = re.sub(r"income[\s_]*tax", "income tax", t)
    t = re.sub(r"\bair\s*tel\b", "airtel", t)
    t = re.sub(r"\bde-?\s?activat", "deactivat", t)
    t = re.sub(r"\bs\s?\.?i\s?\.?m\b", "sim", t)
    t = re.sub(r"\be\.?\s?k\.?\s?y\.?\s?c\b|\bk-y-c\b|\bkycc\b", "kyc", t)
    t = re.sub(r"\bhttps?\s*:?\s*//\s*", "http://", t)
    return t

def scam_hits(text):
    t = strip_ids(normalise(str(text)))
    base = [s for s in base_signals(strip_ids(str(text))) if s != "imperson"]
    hits = list(base)
    if imperson_strict(t): hits.append("imperson")
    hits += [n for n, fn in EXT_RULES.items() if fn(t)]
    return hits

