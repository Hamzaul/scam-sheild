"""Transparent rule-based signals for the project's scam definition.

A message "meets the scam definition" (auto, provisional) if it shows at least one STRONG signal:
  deception to obtain money / OTP / credentials / bank details, organisation impersonation with a
  threat + a way to act, fake-prize claims, advance fees, emergency-family money requests, APK installs.
These are triage heuristics, NOT ground truth: every output must be confirmed by a human reviewer.
"""
import re

URL   = r"(https?://|www\.|\b[a-z0-9-]+\.(?:com|in|net|xyz|co|me|ly|info|org|top|online|site|app|link|cc|tk|ru)\b|bit\.ly|tinyurl|goo\.gl|\bt\.co)"
PHONE = r"(?:\+?\d[\d\s-]{8,}\d|x{7,})"   # x{7,}: digits masked as XXXXXXXXXX in some sources
AUTH = (r"(?:बिजली|बैंक|केवाईसी|पुलिस|आधार|पैन|\b(?:sbi|hdfc|icici|axis|pnb|punjab national|kotak|canara|baroda|yono|paytm|phonepe|gpay|google pay|bhim|upi|rbi|"
        r"uidai|aadhaar|aadhar|pan card|income tax|trai|dot|telecom|police|cbi|cyber ?cell|cyber ?crime|crime branch|customs|narcotics|"
        r"enforcement|court|electricity|bijli|discom|bsnl|jio|airtel|vodafone|india post|post office|fedex|dhl|amazon|flipkart|"
        r"delhivery|blue ?dart|dtdc|ekart|lic|irctc|epfo|bank|kyc|e-?challan|challan|whatsapp|sim)\b)")
THREAT = (r"(?:काट\w*|बंद|ब्लॉक|डिस्कनेक्ट\w*|\bhold\b|\b(?:block\w*|suspend\w*|freez\w*|frozen|deactivat\w*|disconnect\w*|expire[sd]?|expiry|arrest\w*|legal action|penalty|"
          r"seiz\w*|terminat\w*|close[ds]?|cancel\w*|kaat\w*|band ho\w*|banned?|fir|warrant|investigation|fine)\b)")
ACTION = rf"(?:{URL}|{PHONE}|\b(?:click|tap|call|contact|whatsapp|telegram|reply|verify|update|submit|install|download|link|bhejo|bhejein|batao|karein|karo|share)\b)"

_NEG_SHARE = re.compile(
    r"(?:do\s*not|do\s*n'?t|don'?t|never|not|kabhi\s+(?:bhi\s+)?(?:apna\s+)?\w*\s*(?:kisi\s+ko)?)\s+(?:\w+\s+){0,3}?(?:share|disclose|give|tell|reply|forward|dena|batana|batayein|bataye|bataen)\b[^.\n]*"
    r"|\b(?:kisi\s+(?:ko|se)\s+)?(?:share|disclose|dena|batana|batayein|bataye|bataen)\s+(?:mat|na|nahi)\b[^.\n]*", re.I)

CRED_NOUN = r"(?:otp|pin|cvv|password|passcode|card (?:no|number)|account (?:no|number)|aadhaar|aadhar|pan|bank details|net ?banking|login|security code|verification code)"
CRED_VERB = r"(?:share|send|enter|verify|submit|update|provide|tell|forward|reply|bhej\w*|bata\w*|dena|de do|batao|sanga|sang|ivvandi|iyyandi|cheppandi|kodu)"   # + Marathi / Telugu / Kannada 'tell/give'

HI_CRED_NOUN = r"(?:ओटीपी|ओ\.?टी\.?पी|otp|पिन|पासवर्ड|सीवीवी|कार्ड\s*(?:नंबर|संख्या)|खाता\s*(?:नंबर|संख्या)|आधार|पैन|बैंक\s*(?:विवरण|डिटेल))"
HI_CRED_VERB = r"(?:(?:बताइए|बताइये|बताओ|बताएं|बता\s*दीजिए|बता\s*दें|भेजिए|भेजिये|भेजो|भेजें|भेज\s*दें|दीजिए|दीजिये|दें|दो|साझा\s*करें|शेयर\s*करें|सत्यापित\s*करें|दर्ज\s*करें))(?![\u0900-\u0963\u0966-\u097F])"
_NEG_HI = re.compile(r"[^।.\n]*(?:(?<![\u0900-\u097F])न\s*(?:करें|कीजिए|कीजिये|बताएं|बताइए|बताइये|दें)|(?<![\u0900-\u097F])नहीं\s*(?:बताएं|बताइए|दें|करें)|(?<![\u0900-\u097F])मत\s*(?:बताएं|बताओ|दें|दो|करें))[^।.\n]*")

def _cred(t):
    t2 = _NEG_HI.sub(" ", _NEG_SHARE.sub(" ", t))
    return (re.search(rf"\b{CRED_NOUN}\b.{{0,40}}\b{CRED_VERB}\b|\b{CRED_VERB}\b.{{0,40}}\b{CRED_NOUN}\b", t2)
            or re.search(rf"{HI_CRED_NOUN}.{{0,40}}{HI_CRED_VERB}|{HI_CRED_VERB}.{{0,40}}{HI_CRED_NOUN}", t2))

def _fee(t):
    """a fee/deposit is only a signal when the reader is told to PAY it (a bare 'delivery fee' is not)"""
    if re.search(r"\bno\s+(?:hidden\s+|processing\s+)?(?:fee|fees|charge|charges)\b", t): return False
    noun = re.search(r"\b(?:processing|registration|security|clearance|release|refundable|token|activation|customs|advance)\s*(?:fee|fees|charge|charges|deposit|amount)\b", t)
    pay  = re.search(r"\b(?:pay|deposit|transfer|send|remit|submit|jama|bhej\w*|bhar\w*|dena|dijiye|dedo|de do)\b|शुल्क\s*जमा", t)
    return bool(noun and pay)

# pressure = something is demanded or threatened: money/credentials, a coercive consequence, or an instruction to act now.
# An authority claim or an accusation on its own is NOT enough (the text may be a fragment, a notice or a prank).
_PRESSURE = (r"(?:\b(?:fee|fees|charges?|deposit|transfer|payment|pay|bhej\w*|jama|dena hoga|dijiye|rupe\w*|otp|pin|password|cvv|aadhaar number|card number|account number|bank details)\b|₹|\brs\.?\s?\d"
             r"|\b(?:arrest\w*|fir (?:ho chuki|darj|hogi|lag\w*)|jail|warrant|digital arrest|legal action|seiz\w*|freez\w*|frozen|deactivat\w*|block\w*|suspend\w*|disconnect\w*)\b"
             r"|\b(?:turant|abhi|immediately|urgent|jaldi|call karo|call kijiye|video call|do not tell|kisi ko mat|mat batana|link par|click|install|download|sampark)\b)")

RULES = {
 "cred":   _cred,
 "fee":    _fee,
 "prize":  lambda t: re.search(r"\b(?:you(?:'ve| have)? won(?!'t|n't)|has won|have won|winner|lucky draw|lottery|jackpot|awarded|claim)\b", t) and re.search(r"(?:prize|cash|reward|₹|\brs\.?\s?\d|£|\$|lakh|crore|voucher|gift|iphone|\bcar\b)", t) and re.search(ACTION, t),
 "imperson": lambda t: re.search(AUTH, t) and re.search(THREAT, t) and re.search(ACTION, t),
 "authority_call": lambda t: re.search(r"\b(?:police|cbi|cyber ?crime|crime branch|customs|narcotics|enforcement|trai|income tax|court)\b.{0,70}(?:se bol|bol raha|bol rahi|calling|speaking|officer|inspector|department)", t) and re.search(r"\b(?:investigation|case|arrest\w*|freez\w*|frozen|misuse\w*|illegal|verify|verification|sim|account|parcel|fir|warrant)\b", t) and re.search(_PRESSURE, t),
 "family": lambda t: re.search(r"\b(?:mummy|mom|maa|mother|papa|dad|father|beta|bhai|brother|didi|sister|son|daughter|friend|uncle|aunty|relative)\b", t) and re.search(r"\b(?:emergency|hospital|accident|admit\w*|jail|arrest\w*|urgent|turant)\b", t) and re.search(r"\b(?:send|transfer|paise|paisa|pay|account|bhej\w*|bhijwa\w*)\b|₹|\brs\.?\s?\d|\b\d{2,3},?\d{3}\b", t),
 "apk":    lambda t: re.search(r"\.apk\b|install (?:the )?app (?:from|using)", t),
 "job":    lambda t: re.search(r"\b(?:work from home|part[- ]?time|online job|earn|income|task|like and subscribe)\b", t) and re.search(r"(?:per day|daily|a day|per hour|₹\s?\d|\brs\.?\s?\d|\$\s?\d|lakh|guaranteed)", t) and re.search(r"\b(?:telegram|whatsapp|wa\.me|t\.me|register|join)\b", t),
 "parcel": lambda t: re.search(r"\b(?:parcel|package|courier|shipment|consignment)\b", t) and re.search(r"\b(?:held|stuck|failed|incomplete|undeliver\w*|not be delivered|cannot be delivered|could not be delivered|on hold)\b|\baddress\b", t) and re.search(rf"(?:{URL}|{PHONE})", t) and re.search(r"\b(?:confirm|update|reschedule|verify)\b", t),
}
STRONG = tuple(RULES)

def signals(text: str) -> list[str]:
    t = str(text).lower()
    return [name for name, fn in RULES.items() if fn(t)]
