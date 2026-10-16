import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import numpy as np

# Features del dataset PhishStorm
FEATURES = [
    'ranking',
    'mld_res',
    'mld.ps_res',
    'card_rem',
    'ratio_Rrem',
    'ratio_Arem',
    'jaccard_RR',
    'jaccard_RA',
    'jaccard_AR',
    'jaccard_AA',
    'jaccard_ARrd',
    'jaccard_ARrem'
]

print("Cargando dataset PhishStorm...")
df = pd.read_csv("urlset.csv", encoding='latin-1', on_bad_lines='skip')

# Limpiar datos corruptos
for col in FEATURES:
    df[col] = pd.to_numeric(df[col], errors='coerce')
df = df.dropna(subset=FEATURES)
df = df.dropna(subset=['label'])

print(f"Total URLs válidas: {len(df)} — Phishing: {(df['label']==1.0).sum()} — Legítimas: {(df['label']==0.0).sum()}")

X = df[FEATURES].fillna(0).astype(float)
y = (df['label'] == 1.0).astype(int)

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print(f"\nEntrenando Random Forest con {len(X_train)} ejemplos...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\nPrecisión en test: {acc:.4f} ({acc*100:.1f}%)")
print("\nReporte detallado:")
print(classification_report(y_test, y_pred, target_names=["Legítima", "Phishing"]))

# Exportar a ONNX
print("\nExportando modelo a ONNX...")
initial_type = [('float_input', FloatTensorType([None, len(FEATURES)]))]
onnx_model = convert_sklearn(model, initial_types=initial_type)

with open("phishing_model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"Modelo guardado: phishing_model.onnx")
print("\nEntrenamiento completado.")