"""Transparent rule-based signals for the project's scam definition.

A message "meets the scam definition" (auto, provisional) if it shows at least one STRONG signal:
  deception to obtain money / OTP / credentials / bank details, organisation impersonation with a
  threat + a way to act, fake-prize claims, advance fees, emergency-family money requests, APK installs.
These are triage heuristics, NOT ground truth: every output must be confirmed by a human reviewer.
"""
import re

URL   = r"(https?://|www\.|\b[a-z0-9-]+\.(?:com|in|net|xyz|co|me|ly|info|org|top|online|site|app|link|cc|tk|ru)\b|bit\.ly|tinyurl|goo\.gl|\bt\.co)"
PHONE = r"(?:\+?\d[\d\s-]{8,}\d)"
AUTH = (r"(?:बिजली|बैंक|केवाईसी|पुलिस|आधार|पैन|\b(?:sbi|hdfc|icici|axis|pnb|punjab national|kotak|canara|baroda|yono|paytm|phonepe|gpay|google pay|bhim|upi|rbi|"
        r"uidai|aadhaar|aadhar|pan card|income tax|trai|dot|telecom|police|cbi|cyber ?cell|cyber ?crime|crime branch|customs|narcotics|"
        r"enforcement|court|electricity|bijli|discom|bsnl|jio|airtel|vodafone|india post|post office|fedex|dhl|amazon|flipkart|"
        r"delhivery|blue ?dart|dtdc|ekart|lic|irctc|epfo|bank|kyc|e-?challan|challan|whatsapp|sim)\b)")
THREAT = (r"(?:काट\w*|बंद|ब्लॉक|डिस्कनेक्ट\w*|\bhold\b|\b(?:block\w*|suspend\w*|freez\w*|frozen|deactivat\w*|disconnect\w*|expire[sd]?|expiry|arrest\w*|legal action|penalty|"
          r"seiz\w*|terminat\w*|close[ds]?|cancel\w*|kaat\w*|band ho\w*|banned?|fir|warrant|investigation|fine)\b)")
ACTION = rf"(?:{URL}|{PHONE}|\b(?:click|tap|call|contact|whatsapp|telegram|reply|verify|update|submit|install|download|link|bhejo|bhejein|batao|karein|karo|share)\b)"

_NEG_SHARE = re.compile(
    r"(?:do not|don'?t|never|not|kabhi\s+(?:bhi\s+)?(?:apna\s+)?\w*\s*(?:kisi\s+ko)?)\s+(?:\w+\s+){0,3}?(?:share|disclose|give|tell|dena|batana|batayein|bataye|bataen)\b[^.\n]*"
    r"|\b(?:kisi\s+(?:ko|se)\s+)?(?:share|disclose|dena|batana|batayein|bataye|bataen)\s+(?:mat|na|nahi)\b[^.\n]*", re.I)

CRED_NOUN = r"(?:otp|pin|cvv|password|passcode|card (?:no|number)|account (?:no|number)|aadhaar|aadhar|pan|bank details|net ?banking|login|security code|verification code)"
CRED_VERB = r"(?:share|send|enter|verify|submit|update|provide|tell|forward|reply|bhej\w*|bata\w*|dena|de do|batao)"

RULES = {
 "cred":   lambda t: re.search(rf"\b{CRED_NOUN}\b.{{0,40}}\b{CRED_VERB}\b|\b{CRED_VERB}\b.{{0,40}}\b{CRED_NOUN}\b", _NEG_SHARE.sub(" ", t)),
 "fee":    lambda t: re.search(r"\b(?:processing|registration|security|verification|delivery|customs|clearance|release|handling|insurance|advance|refundable|token|activation)\s*(?:fee|fees|charge|charges|deposit)\b", t) and not re.search(r"\bno\s+(?:hidden\s+|processing\s+)?(?:fee|fees|charge|charges)\b", t),
 "prize":  lambda t: re.search(r"\b(?:you(?:'ve| have)? won|has won|have won|winner|lucky draw|lottery|jackpot|awarded|claim)\b", t) and re.search(r"(?:prize|cash|reward|₹|\brs\.?\s?\d|£|\$|lakh|crore|voucher|gift|iphone|\bcar\b)", t) and re.search(ACTION, t),
 "imperson": lambda t: re.search(AUTH, t) and re.search(THREAT, t) and re.search(ACTION, t),
 "authority_call": lambda t: re.search(r"\b(?:police|cbi|cyber ?crime|crime branch|customs|narcotics|enforcement|trai|income tax|court)\b.{0,70}(?:se bol|bol raha|bol rahi|calling|speaking|officer|inspector|department)", t) and re.search(r"\b(?:investigation|case|arrest\w*|freez\w*|frozen|misuse\w*|illegal|verify|verification|sim|account|parcel|fir|warrant)\b", t),
 "family": lambda t: re.search(r"\b(?:mummy|mom|maa|papa|dad|beta|bhai|didi|son|daughter|friend)\b", t) and re.search(r"\b(?:emergency|hospital|accident|admit\w*|jail|arrest\w*|urgent)\b", t) and re.search(r"\b(?:send|transfer|paise|paisa|pay|account)\b|₹|\brs\.?\s?\d", t),
 "apk":    lambda t: re.search(r"\.apk\b|install (?:the )?app (?:from|using)", t),
 "job":    lambda t: re.search(r"\b(?:work from home|part[- ]?time|online job|earn|income|task|like and subscribe)\b", t) and re.search(r"(?:per day|daily|a day|per hour|₹\s?\d|\brs\.?\s?\d|\$\s?\d|lakh|guaranteed)", t) and re.search(r"\b(?:telegram|whatsapp|wa\.me|t\.me|register|join)\b", t),
 "parcel": lambda t: re.search(r"\b(?:parcel|package|courier|shipment|consignment)\b", t) and re.search(r"\b(?:held|stuck|failed|address|incomplete|undeliver\w*|not be delivered|customs|pending)\b", t) and re.search(rf"(?:{URL}|{PHONE})", t) and re.search(r"\b(?:confirm|update|pay|reschedule|fee|verify)\b", t),
}
STRONG = tuple(RULES)

def signals(text: str) -> list[str]:
    t = str(text).lower()
    return [name for name, fn in RULES.items() if fn(t)]
