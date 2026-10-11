import re
import random
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy.sparse import hstack, csr_matrix
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix,
                             classification_report, ConfusionMatrixDisplay)

CSV_PATH = None
random.seed(42)
np.random.seed(42)

def build_sample_dataset(n_each=300):
    phish_templates = [
        "URGENT: Your {acct} account has been suspended. Verify your password immediately at {url} or it will be closed.",
        "Dear customer, we detected unusual login activity. Click {url} to confirm your identity and update your bank details now.",
        "Congratulations! You have won a ${amt} gift card. Claim your prize now: {url} Limited time offer!!!",
        "Security alert: your {acct} has been locked. Login here {url} and verify your account to avoid permanent suspension.",
        "Your payment failed. Update your credit card information immediately: {url} Act now!",
        "Final notice: confirm your OTP and password at {url} within 24 hours or lose access to your {acct}.",
        "You have a pending refund of ${amt}. Click the link {url} and enter your card number and PIN to receive it.",
        "Dear user, your mailbox is full. Click {url} to verify your email and avoid account termination!!",
    ]
    legit_templates = [
        "Hi team, the meeting is scheduled for {day} at {time}. Please find the agenda attached. Thanks, {name}",
        "Hello {name}, thanks for your order. Your invoice is attached and the package will ship in 3 business days.",
        "Reminder: the project report is due on {day}. Let me know if you need any help with the data analysis.",
        "Hi {name}, can we reschedule our call to {day}? I have a conflict in the morning. Best regards.",
        "Please review the attached notes from today's class. The assignment is due next {day}. See you in the lab.",
        "Dear {name}, your internship certificate is ready. You can download it from the official portal at {safe_url}.",
        "Thanks for attending the webinar! The slides and recording are available at {safe_url}. Regards, {name}",
        "Happy birthday {name}! Wishing you a great year ahead. Lunch is on us on {day}.",
    ]
    accts = ["PayPal", "bank", "Amazon", "Netflix", "Apple ID", "Microsoft"]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
    names = ["Priya", "Arun", "Kavya", "Rahul", "Meena", "Vikram"]
    safe_urls = ["https://www.thiranex.com/portal", "https://www.google.com/docs", "https://github.com/team/project"]

    def phish_url():
        return random.choice([
            f"http://{random.randint(10,200)}.{random.randint(1,250)}.{random.randint(1,250)}.{random.randint(1,250)}/login",
            f"http://secure-{random.choice(['paypal','amazon','bank'])}-verify.{random.choice(['xyz','top','tk'])}/update",
            f"https://bit.ly/{random.choice(['3xYz','Ab12','Qw9p'])}",
            f"http://account-login.{random.choice(['ru','info','biz'])}/confirm?id={random.randint(1000,9999)}",
        ])

    rows = []
    for _ in range(n_each):
        t = random.choice(phish_templates).format(
            acct=random.choice(accts), url=phish_url(), amt=random.randint(100, 5000))
        rows.append((t, 1))
        t = random.choice(legit_templates).format(
            name=random.choice(names), day=random.choice(days),
            time=f"{random.randint(9,17)}:00", safe_url=random.choice(safe_urls))
        rows.append((t, 0))
    df = pd.DataFrame(rows, columns=["text", "label"])
    return df.sample(frac=1, random_state=42).reset_index(drop=True)

if CSV_PATH:
    df = pd.read_csv(CSV_PATH)[["text", "label"]].dropna()
else:
    df = build_sample_dataset()

print("Dataset size:", len(df))
print(df["label"].value_counts().rename({1: "Phishing", 0: "Safe"}), "\n")

URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
IP_REGEX = re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}")
SHORTENERS = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly", "is.gd"]
SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ru", ".biz", ".info"]
KEYWORDS = ["urgent", "verify", "password", "suspended", "account", "login", "click",
            "confirm", "bank", "otp", "pin", "winner", "prize", "claim", "immediately",
            "limited", "security", "alert", "refund", "credit card", "update", "locked"]

def extract_features(text):
    t = text.lower()
    urls = URL_REGEX.findall(text)
    return [
        len(urls),
        int(bool(IP_REGEX.search(text))),
        int(any(s in t for s in SHORTENERS)),
        int(any(tld in t for tld in SUSPICIOUS_TLDS)),
        max([len(u) for u in urls], default=0),
        int(any(u.lower().startswith("http://") for u in urls)),
        sum(k in t for k in KEYWORDS),
        text.count("!"),
        sum(c.isupper() for c in text) / max(len(text), 1),
        len(text),
    ]

X_text = df["text"].astype(str)
y = df["label"].astype(int)
X_feat = np.array([extract_features(t) for t in X_text])

idx_train, idx_test = train_test_split(
    np.arange(len(df)), test_size=0.2, random_state=42, stratify=y)

tfidf = TfidfVectorizer(stop_words="english", max_features=3000, ngram_range=(1, 2))
scaler = StandardScaler()

Xtr_tfidf = tfidf.fit_transform(X_text.iloc[idx_train])
Xte_tfidf = tfidf.transform(X_text.iloc[idx_test])
Xtr_feat = scaler.fit_transform(X_feat[idx_train])
Xte_feat = scaler.transform(X_feat[idx_test])

X_train = hstack([Xtr_tfidf, csr_matrix(Xtr_feat)]).tocsr()
X_test = hstack([Xte_tfidf, csr_matrix(Xte_feat)]).tocsr()
y_train, y_test = y.iloc[idx_train], y.iloc[idx_test]

model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print(f"Accuracy: {acc * 100:.2f}%\n")
print("Confusion Matrix:\n", cm, "\n")
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))

disp = ConfusionMatrixDisplay(cm, display_labels=["Safe", "Phishing"])
disp.plot(cmap="Blues", values_format="d")
plt.title(f"Confusion Matrix (Accuracy: {acc * 100:.2f}%)")
plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=150)
plt.show()

def classify_email(text):
    feats = scaler.transform([extract_features(text)])
    vec = hstack([tfidf.transform([text]), csr_matrix(feats)]).tocsr()
    pred = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0][pred]
    return ("Phishing" if pred == 1 else "Safe"), prob

samples = [
    "URGENT! Your bank account is suspended. Verify your password now at http://192.168.4.22/login",
    "Hi Priya, the meeting is on Friday at 10:00. Agenda attached. Thanks!",
    "Congratulations winner! Claim your $1000 prize immediately: https://bit.ly/3xYz",
]
print("\n--- Sample Predictions ---")
for s in samples:
    label, conf = classify_email(s)
    print(f"[{label} | {conf * 100:.1f}%] {s}")
