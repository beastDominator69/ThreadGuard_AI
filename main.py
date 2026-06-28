import os
import re
import pickle
import base64
import json
from html import unescape
from flask import Flask, render_template, request, jsonify
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from groq import Groq
import socket
from urllib.parse import urlparse
from datetime import datetime
from dotenv import load_dotenv
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(24))

# REPLACE WITH THIS
load_dotenv()
groq_client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)
AVAILABLE_MODELS = [
    "llama-3.3-70b-versatile",
    "llama-3.1-8b-instant",
]
SELECTED_MODEL = "llama-3.3-70b-versatile"

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Stats file
STATS_FILE = 'threatguard_stats.json'

# ============================================
# STATS MANAGEMENT WITH REAL ACCURACY
# ============================================

def load_stats():
    """Load stats from JSON file"""
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r') as f:
                return json.load(f)
    except:
        pass
    return {
        'total_scans': 0,
        'total_threats': 0,
        'total_safe': 0,
        'correct_predictions': 0,
        'accuracy': 0.0,
        'last_updated': datetime.now().isoformat()
    }

def save_stats(stats):
    """Save stats to JSON file"""
    stats['last_updated'] = datetime.now().isoformat()
    with open(STATS_FILE, 'w') as f:
        json.dump(stats, f, indent=2)

def validate_prediction(verdict, text):
    """
    Simple but effective validation using weighted scoring
    Returns: (is_correct, is_threat)
    """
    lower_text = text.lower()
    
    # Weighted phishing indicators
    high_risk = ['password', 'credit card', 'social security', 'atm pin', 
                 'bank account', 'verify identity', 'suspended', 'closure',
                 'wire transfer', 'gift card', 'itunes card']
    
    medium_risk = ['urgent', 'immediate', 'click here', 'login now', 
                   'confirm', 'update', 'billing', 'payment',
                   'limited time', 'act now', 'verify your account']
    
    low_risk = ['security', 'alert', 'notification', 'warning', 
                'important', 'attention', 'required', 'review']
    
    # Calculate risk score
    score = 0
    for word in high_risk:
        if word in lower_text:
            score += 3
    for word in medium_risk:
        if word in lower_text:
            score += 2
    for word in low_risk:
        if word in lower_text:
            score += 1
    
    # Check for trusted sender
    trusted_domains = [
        '@google.com', '@microsoft.com', '@apple.com', '@amazon.com',
        '@paypal.com', '@gmail.com', '@outlook.com', '@yahoo.com',
        '@github.com', '@stackoverflow.com', '@wikipedia.org',
        '.gov', '.edu', '.org', '@bank', '@secure', '@support'
    ]
    is_trusted = any(domain in lower_text for domain in trusted_domains)
    
    # Check for suspicious sender patterns
    suspicious_senders = ['@gmail.com', '@outlook.com', '@yahoo.com', '@hotmail.com']
    is_free_email = any(sender in lower_text for sender in suspicious_senders)
    
    # Determine ground truth
    is_actually_scam = False
    is_actually_safe = False
    
    # If high risk score + not trusted = scam
    if score >= 4 and not is_trusted:
        is_actually_scam = True
    # If high risk score even from trusted sender = still possible scam
    elif score >= 6:
        is_actually_scam = True
    # If trusted sender and low risk = safe
    elif is_trusted and score <= 2:
        is_actually_safe = True
    # If free email + medium risk = suspicious (treat as scam)
    elif is_free_email and score >= 3:
        is_actually_scam = True
    # If very low risk = safe
    elif score <= 1:
        is_actually_safe = True
    # If unknown, default to safe
    else:
        is_actually_safe = True
    
    # AI's verdict
    ai_says_scam = any(word in verdict.lower() for word in ['scam', 'fake', 'malicious', 'phishing'])
    ai_says_safe = any(word in verdict.lower() for word in ['legitimate', 'safe', 'secure'])
    
    # Validate
    is_correct = False
    
    if is_actually_scam and ai_says_scam:
        is_correct = True
    elif is_actually_safe and ai_says_safe:
        is_correct = True
    elif is_actually_scam and ai_says_safe:
        is_correct = False
    elif is_actually_safe and ai_says_scam:
        is_correct = False
    
    return is_correct, is_actually_scam

def validate_url_prediction(verdict, url):
    """
    Validate URL prediction
    Returns: (is_correct, is_threat)
    """
    lower_url = url.lower()
    
    # Suspicious extensions (expanded list)
    suspicious_extensions = [
        '.xyz', '.cc', '.top', '.gq', '.ml', '.tk', '.cf',
        '.click', '.download', '.stream', '.cyou', '.men',
        '.work', '.date', '.trade', '.loan', '.win', '.bid',
        '.review', '.webcam', '.science', '.tech', '.live'
    ]
    has_suspicious_ext = any(ext in lower_url for ext in suspicious_extensions)
    
    # Typosquatting patterns (expanded)
    typosquatting = {
        'paypa1': 'paypal', 'paypai': 'paypal', 'pay-pal': 'paypal',
        'facebok': 'facebook', 'facebo0k': 'facebook', 'fbacebook': 'facebook',
        'g00gle': 'google', 'go0gle': 'google', 'gogle': 'google',
        'amaz0n': 'amazon', 'amazn': 'amazon', 'amazzon': 'amazon',
        'micr0soft': 'microsoft', 'micros0ft': 'microsoft',
        'app1e': 'apple', 'appple': 'apple',
        'netfl1x': 'netflix', 'netflx': 'netflix'
    }
    is_typosquatting = any(fake in lower_url for fake in typosquatting.keys())
    
    # Short URL services (often used in phishing)
    short_urls = ['bit.ly', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
                  'short.link', 'goo.gl', 't.co', 'fb.me', 'youtu.be',
                  'tiny.cc', 'shorturl.at', 'rb.gy', 'cutt.ly']
    uses_short_url = any(short in lower_url for short in short_urls)
    
    # Safe domains
    safe_domains = [
        'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
        'apple.com', 'paypal.com', 'github.com', 'stackoverflow.com',
        'wikipedia.org', 'youtube.com', 'twitter.com', 'linkedin.com',
        'instagram.com', 'whatsapp.com', 'netflix.com', 'spotify.com'
    ]
    is_safe_domain = any(domain in lower_url for domain in safe_domains)
    
    # Determine ground truth
    is_actually_malicious = has_suspicious_ext or is_typosquatting or uses_short_url
    is_actually_safe = is_safe_domain and not is_actually_malicious
    
    # If it's a short URL, mark as suspicious
    if uses_short_url:
        is_actually_malicious = True
    
    # AI's verdict
    ai_says_malicious = any(word in verdict.lower() for word in ['malicious', 'phishing'])
    ai_says_safe = any(word in verdict.lower() for word in ['legitimate', 'safe'])
    
    # Validate
    is_correct = False
    
    if is_actually_malicious and ai_says_malicious:
        is_correct = True
    elif is_actually_safe and ai_says_safe:
        is_correct = True
    elif is_actually_malicious and ai_says_safe:
        is_correct = False
    elif is_actually_safe and ai_says_malicious:
        is_correct = False
    
    return is_correct, is_actually_malicious

def update_stats(is_threat, is_correct=True):
    """Update stats with validation"""
    stats = load_stats()
    stats['total_scans'] += 1
    
    if is_threat:
        stats['total_threats'] += 1
    else:
        stats['total_safe'] += 1
    
    if is_correct:
        stats['correct_predictions'] += 1
    
    # Calculate REAL accuracy
    if stats['total_scans'] > 0:
        accuracy = (stats['correct_predictions'] / stats['total_scans']) * 100
        stats['accuracy'] = round(min(99.9, accuracy), 1)
    
    save_stats(stats)
    return stats

# ============================================
# EXISTING FUNCTIONS (UNCHANGED)
# ============================================

def get_gmail_service():
    creds = None
    token_path = 'token.pickle'

    if os.path.exists(token_path):
        with open(token_path, 'rb') as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, 'wb') as token:
            pickle.dump(creds, token)

    return build('gmail', 'v1', credentials=creds)


def strip_html(html_text):
    text = re.sub(r'<(script|style)[^>]*>.*?</\1>', ' ', html_text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = unescape(text)
    return re.sub(r'\s+', ' ', text).strip()


def extract_body_from_payload(payload):
    plain_body = ""
    html_body = ""

    def walk(part):
        nonlocal plain_body, html_body
        mime_type = part.get('mimeType', '')
        body_data = part.get('body', {}).get('data')

        if mime_type == 'text/plain' and body_data and not plain_body:
            plain_body = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')
        elif mime_type == 'text/html' and body_data and not html_body:
            html_body = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

        for sub_part in part.get('parts', []):
            walk(sub_part)

    walk(payload)

    if plain_body.strip():
        return plain_body
    if html_body.strip():
        return strip_html(html_body)
    return ""


def analyze_email(text):
    lower = text.lower()

    # EXPANDED trusted patterns
    trusted_patterns = [
        "@google.com", "@microsoft.com", "@apple.com", "@amazon.com",
        "@meta.com", "@facebook.com", "@twitter.com", "@linkedin.com",
        "@github.com", "@gitlab.com", "@bitbucket.org",
        "@paypal.com", "@stripe.com", "@square.com", "@venmo.com",
        "@wise.com", "@transferwise.com", "@revolut.com",
        "@telenorbank.pk", "@habibbankltd.com", "@mcb.com.pk", "@ubl.com.pk",
        "@alfalah.com", "@bankalfalah.com", "@mcbank.com", "@jsbank.com",
        "@standardchartered.com", "@soneribank.com", "@askaribank.com",
        "@bankislami.com.pk", "@faysalbank.com", "@silkbank.com.pk",
        "@summitbank.com.pk", "@bankalhabib.com", "@meezanbank.com",
        "@citibank.com", "@hsbc.com", "@bankofamerica.com", "@wellsfargo.com",
        "@chase.com", "@barclays.com", "@lloydsbank.com", "@natwest.com",
        "@gmail.com", "@outlook.com", "@yahoo.com", "@hotmail.com",
        "@aol.com", "@protonmail.com", "@zoho.com", "@icloud.com",
        ".gov.pk", ".edu.pk", ".gov", ".edu", ".ac.uk", ".edu.au",
        ".gov.uk", ".gov.au", ".gc.ca", ".gov.in", ".nic.in",
        "@salesforce.com", "@adobe.com", "@oracle.com", "@ibm.com",
        "@atlassian.com", "@slack.com", "@zoom.us", "@dropbox.com",
        "@instagram.com", "@whatsapp.com", "@spotify.com", "@netflix.com",
        "@ebay.com", "@etsy.com", "@walmart.com", "@daraz.pk",
        "@telenor.com.pk", "@jazz.com.pk", "@zong.com.pk", "@ufone.com",
        "@dhl.com", "@fedex.com", "@ups.com", "@tcs.com.pk",
        "@booking.com", "@airbnb.com", "@pia.com.pk",
        "@dawn.com", "@tribune.com.pk", "@geo.tv",
        "@k-electric.com", "@lesco.gov.pk",
        "no-reply@", "noreply@", "donotreply@", "notifications@",
        "alerts@", "security@", "support@", "help@", "info@",
    ]

    is_trusted_sender = False
    sender_domain = ""

    sender_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    if sender_match:
        sender_email = sender_match.group(0).lower()
        sender_domain = "@" + sender_email.split("@")[-1]
        for pattern in trusted_patterns:
            if pattern in sender_email:
                is_trusted_sender = True
                break

    if not is_trusted_sender:
        common_legit_patterns = [
            "statement@", "e.statement@", "estatement@",
            "notification@", "alert@", "update@", "newsletter@",
            "receipt@", "invoice@", "billing@", "payment@",
            "confirm@", "verification@", "welcome@",
        ]
        for pattern in common_legit_patterns:
            if pattern in lower:
                is_trusted_sender = True
                break

    # EXPANDED phishing red flags
    phishing_red_flags = [
        # Existing
        "your account will be suspended", "immediate action required",
        "act now or lose access", "final warning", "account closure",
        "enter your password", "confirm your credit card",
        "social security number", "bank account number", "atm pin",
        "click here to login", "verify your identity here",
        "secure your account now", "dear costumer", "dear user",
        "dear valued", "kindly do the needful", "revert back",
        "urgently required",
        # NEW
        "verify your account", "update your billing information",
        "suspicious activity detected", "unauthorized transaction",
        "limited access", "confirm your identity", "security breach",
        "reactivate your account", "restore your account",
        "unusual login attempt", "new device detected",
        "pending payment", "overdue invoice", "claim your prize",
        "you have been selected", "congratulations you won",
        "free gift", "exclusive offer", "limited time offer",
        "click to confirm", "scan the qr code", "download attachment",
        "enable two factor", "change your password now",
        "gift card", "itunes card", "wire transfer",
        "western union", "money gram", "cryptocurrency",
        "bitcoin", "pay with", "microsoft support", "apple support"
    ]
    strong_red_flags_count = sum(1 for flag in phishing_red_flags if flag in lower)

    if is_trusted_sender:
        if strong_red_flags_count >= 3:
            prompt_context = f"This email appears to be from a trusted sender ({sender_domain}) but has multiple red flags. Analyze carefully."
        else:
            prompt_context = f"This email is from a trusted sender ({sender_domain}). Bank statements, transaction alerts, and security notifications from such senders are typically legitimate unless they show clear phishing signs."
    else:
        if strong_red_flags_count >= 2:
            prompt_context = "This email is from an untrusted sender and has multiple phishing indicators. Analyze critically."
        else:
            prompt_context = "Analyze this email for potential phishing attempts."

    prompt = f"""
{prompt_context}

Analyze this email for legitimacy:

GUIDELINES:
1. Bank statements, transaction alerts, security notifications from trusted domains are USUALLY LEGITIMATE
2. Look for mismatches between sender name and email domain
3. Check if links go to official domains (not shortened URLs)
4. Real companies rarely ask for passwords via email
5. Poor grammar/spelling often indicates phishing
6. Excessive urgency/panic is suspicious
7. Requests for gift cards, wire transfers, or cryptocurrency are ALWAYS scams
8. Check for typos in domain names (e.g., paypa1.com instead of paypal.com)

Respond EXACTLY in this format:
VERDICT: [Scam/Fake or Legitimate/Safe]
REASON: [Detailed analysis. If legitimate, explain why. If scam, list specific red flags.]
HIGHLIGHTED: [The original email with ONLY ACTUAL suspicious parts in **bold**]

Email Content:
{text[:3900]}
"""

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=SELECTED_MODEL,
            temperature=0.1,
            max_tokens=1024,
        )
        raw = chat_completion.choices[0].message.content

        verdict = "Legitimate/Safe"
        reason = "Analysis completed"
        highlighted = text

        for line in raw.split('\n'):
            if line.startswith("VERDICT:"):
                verdict = line.split(":", 1)[1].strip()
            elif line.startswith("REASON:"):
                reason = line.split(":", 1)[1].strip()
            elif line.startswith("HIGHLIGHTED:"):
                highlighted = line.split(":", 1)[1].strip()

        if is_trusted_sender and ("scam" in verdict.lower() or "fake" in verdict.lower()):
            reason = f"⚠️ CAUTION: This appears to be from trusted domain {sender_domain}, but shows phishing signs. " + reason

        return {"verdict": verdict, "reason": reason, "highlighted": highlighted}

    except Exception as e:
        print(f"AI Analysis Error: {e}")
        if is_trusted_sender:
            return {
                "verdict": "Legitimate/Safe",
                "reason": f"AI unavailable - Email from trusted domain {sender_domain}",
                "highlighted": text,
            }
        return {
            "verdict": "Unknown - Manual Review Needed",
            "reason": f"AI analysis failed. Sender domain: {sender_domain if sender_domain else 'Unknown'}",
            "highlighted": text,
        }

def domain_exists(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain == "":
            return False
        socket.getaddrinfo(domain, None)
        return True
    except socket.gaierror:
        return False
    except:
        return False


def analyze_url_with_ai(url):
    print("Checking:", url)
    print("Exists:", domain_exists(url))

    url = url.strip()

    if url == "":
        return {
            "verdict": "Invalid URL",
            "reason": "No URL entered",
            "confidence": "High"
        }

    if not domain_exists(url):
        return {
            "verdict": "Website Not Found",
            "reason": "This domain does not exist or cannot be resolved.",
            "confidence": "High"
        }

    lower_url = url.lower()

    # EXPANDED suspicious domains
    suspicious_domains = [
        '.xyz', '.cc', '.top', '.gq', '.ml', '.tk', '.cf',
        '.click', '.download', '.stream', '.cyou', '.men',
        '.work', '.date', '.trade', '.loan', '.win', '.bid',
        '.review', '.webcam', '.science', '.tech', '.live'
    ]

    for ext in suspicious_domains:
        if ext in lower_url:
            return {
                "verdict": "Malicious/Phishing",
                "reason": f"Suspicious domain extension ({ext}) commonly used for phishing.",
                "confidence": "High"
            }

    # Short URL services
    short_urls = ['bit.ly', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly',
                  'short.link', 'goo.gl', 't.co', 'fb.me', 'youtu.be',
                  'tiny.cc', 'shorturl.at', 'rb.gy', 'cutt.ly']
    for short in short_urls:
        if short in lower_url:
            return {
                "verdict": "Suspicious/Review",
                "reason": f"URL uses a short link service ({short}), commonly used to hide malicious destinations.",
                "confidence": "Medium"
            }

    # EXPANDED typosquatting
    popular_domains = {
        "paypal": ["paypa1", "paypai", "pay-pal", "paypall"],
        "facebook": ["facebok", "facebo0k", "fbacebook", "face-book"],
        "google": ["g00gle", "go0gle", "gogle", "gooogle"],
        "amazon": ["amaz0n", "amazn", "amazzon", "amazoon"],
        "microsoft": ["micr0soft", "micros0ft", "mircosoft", "micro-soft"],
        "apple": ["app1e", "appple", "appIe"],
        "netflix": ["netfl1x", "netfiix", "netflx"]
    }

    for legit, fakes in popular_domains.items():
        for fake in fakes:
            if fake in lower_url:
                return {
                    "verdict": "Malicious/Phishing",
                    "reason": f"Domain impersonating {legit} (typosquatting attack).",
                    "confidence": "High"
                }

    # AI analysis
    prompt = f"""
You are a cybersecurity expert.

Analyze this URL:

{url}

Check:
1. Is the domain suspicious?
2. Is it impersonating a known brand?
3. Does it contain phishing keywords?
4. Is it safe?
5. Is it a short URL (e.g., bit.ly, tinyurl.com)?

Respond EXACTLY:
VERDICT: Legitimate/Safe OR Malicious/Phishing OR Suspicious/Review
REASON: Explain briefly.
CONFIDENCE: High/Medium/Low
"""

    try:
        chat_completion = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=SELECTED_MODEL,
            temperature=0.1,
            max_tokens=300
        )
        raw = chat_completion.choices[0].message.content

        verdict = "Unknown"
        reason = "Unable to analyze"
        confidence = "Low"

        for line in raw.split('\n'):
            if line.startswith("VERDICT:"):
                verdict = line.split(":",1)[1].strip()
            elif line.startswith("REASON:"):
                reason = line.split(":",1)[1].strip()
            elif line.startswith("CONFIDENCE:"):
                confidence = line.split(":",1)[1].strip()

        return {
            "verdict": verdict,
            "reason": reason,
            "confidence": confidence
        }

    except Exception as e:
        print(e)
        return {
            "verdict": "Unknown - Manual Review Needed",
            "reason": "AI analysis failed",
            "confidence": "Low"
        }

# ============================================
# ROUTES WITH ACCURACY TRACKING
# ============================================

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Return current statistics"""
    stats = load_stats()
    return jsonify(stats)

@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '')
    analysis = analyze_url_with_ai(url)
    verdict = analysis["verdict"].lower()
    
    if "malicious" in verdict or "phishing" in verdict:
        predicted_class = "malicious"
        is_threat = True
    elif "suspicious" in verdict or "review" in verdict:
        predicted_class = "suspicious"
        is_threat = True  # Treat as threat for safety
    elif "website not found" in verdict:
        predicted_class = "not_found"
        is_threat = False
    else:
        predicted_class = "legitimate"
        is_threat = False
    
    # Validate the prediction
    is_correct, actual_threat = validate_url_prediction(verdict, url)
    
    # Update stats with real accuracy
    update_stats(is_threat, is_correct)

    return render_template(
        'index.html',
        input_url=url,
        predicted_class=predicted_class,
        url_reason=f"{analysis['reason']} (Confidence: {analysis['confidence']})"
    )


@app.route('/scam/', methods=['POST'])
def analyze_file():
    if 'file' not in request.files:
        return render_template('index.html', file_result="No file uploaded")

    file = request.files['file']
    if file.filename == '':
        return render_template('index.html', file_result="No file selected")

    try:
        if file.filename.endswith('.txt'):
            content = file.read().decode('utf-8', errors='ignore')

        elif file.filename.endswith('.pdf'):
            try:
                import PyPDF2
                import io
                pdf_reader = PyPDF2.PdfReader(io.BytesIO(file.read()))
                content = "".join(page.extract_text() for page in pdf_reader.pages)
                if not content.strip():
                    content = "PDF file is empty or text could not be extracted."
            except ImportError:
                return render_template('index.html',
                                        file_result="Error",
                                        file_reason="PyPDF2 not installed. Run: pip install PyPDF2",
                                        file_highlighted="Install the required library to analyze PDF files.")
            except Exception as e:
                content = f"PDF extraction error: {str(e)}"
        else:
            return render_template('index.html',
                                    file_result="Unsupported Format",
                                    file_reason="Only .txt and .pdf files are supported",
                                    file_highlighted="Please upload a .txt or .pdf file")

        if content and "not fully implemented" not in content and "PDF extraction error" not in content:
            analysis = analyze_email(content)
            keywords = ['urgent', 'password', 'verify', 'click', 'link', 'suspended', 'account',
                        'payment', 'security', 'login', 'confirm', 'update', 'billing']
            found_keywords = [kw for kw in keywords if kw in content.lower()]
            
            # Check if it's a threat
            is_threat = "scam" in analysis["verdict"].lower() or "fake" in analysis["verdict"].lower()
            
            # Validate the prediction
            is_correct, actual_threat = validate_prediction(analysis["verdict"], content)
            
            # Update stats with real accuracy
            update_stats(is_threat, is_correct)

            return render_template('index.html',
                                    file_result=analysis["verdict"],
                                    file_reason=analysis["reason"],
                                    file_keywords=found_keywords if found_keywords else None,
                                    file_highlighted=analysis["highlighted"])
        else:
            return render_template('index.html',
                                    file_result="Cannot Analyze",
                                    file_reason=content if content else "File is empty",
                                    file_highlighted="Upload a text-based file with readable content")

    except Exception as e:
        return render_template('index.html',
                                file_result=f"Error: {str(e)[:100]}",
                                file_reason="File processing failed",
                                file_highlighted="Try uploading a simpler text file")


@app.route('/email/', methods=['POST'])
def analyze_email_text():
    email_text = request.form.get('email_text', '')
    if not email_text:
        return render_template('index.html', email_result="No email text provided")

    analysis = analyze_email(email_text)
    
    # Check if it's a threat
    is_threat = "scam" in analysis["verdict"].lower() or "fake" in analysis["verdict"].lower()
    
    # Validate the prediction
    is_correct, actual_threat = validate_prediction(analysis["verdict"], email_text)
    
    # Update stats with real accuracy
    update_stats(is_threat, is_correct)
    
    return render_template('index.html',
                            email_result=analysis["verdict"],
                            email_reason=analysis["reason"],
                            highlighted_email=analysis["highlighted"])


@app.route('/')
def landing():
    return render_template('landing.html')


@app.route('/dashboard')
def index():
    return render_template('index.html')


@app.route('/connect-gmail')
def connect_gmail():
    try:
        service = get_gmail_service()
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        emails = []
        threat_count = 0
        correct_count = 0

        for msg in messages:
            try:
                m = service.users().messages().get(userId='me', id=msg['id']).execute()
                headers = m['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')

                body = extract_body_from_payload(m['payload'])

                full_text = f"From: {sender}\nSubject: {subject}\n\n{body[:500]}"
                analysis = analyze_email(full_text)
                
                # Check if it's a threat
                is_threat = "scam" in analysis["verdict"].lower() or "fake" in analysis["verdict"].lower()
                
                # Validate the prediction
                is_correct, actual_threat = validate_prediction(analysis["verdict"], full_text)
                
                # Track stats
                threat_count += 1 if is_threat else 0
                correct_count += 1 if is_correct else 0
                
                emails.append({
                    "sender": sender,
                    "subject": subject[:50],
                    "verdict": analysis["verdict"],
                    "reason": analysis["reason"],
                    "highlighted": analysis["highlighted"],
                })
            except Exception as e:
                print(f"Error processing email: {e}")
                continue

        # Update stats with Gmail scan
        if emails:
            stats = load_stats()
            stats['total_scans'] += len(emails)
            stats['total_threats'] += threat_count
            stats['total_safe'] += len(emails) - threat_count
            stats['correct_predictions'] = stats.get('correct_predictions', 0) + correct_count
            
            # Calculate real accuracy
            if stats['total_scans'] > 0:
                stats['accuracy'] = round((stats['correct_predictions'] / stats['total_scans']) * 100, 1)
            
            save_stats(stats)

        if not emails:
            return render_template('index.html', gmail_error="No emails found or unable to process emails")

        return render_template('index.html', gmail_emails=emails)

    except Exception as e:
        print(f"Gmail Connection Error: {e}")
        return render_template('index.html', gmail_error=f"Failed to connect: {str(e)[:50]}...")


if __name__ == '__main__':
    # Initialize stats file if it doesn't exist
    if not os.path.exists(STATS_FILE):
        save_stats({
            'total_scans': 0,
            'total_threats': 0,
            'total_safe': 0,
            'correct_predictions': 0,
            'accuracy': 0.0
        })
    
    print("🚀 ThreatGuard is LIVE → http://127.0.0.1:8080")
    print("📊 Using Groq API with Llama 3.3 70B")
    print("📈 Real Accuracy Tracking Enabled")
    print("📁 Stats saved to:", STATS_FILE)
    app.run(debug=True, host='127.0.0.1', port=8080)