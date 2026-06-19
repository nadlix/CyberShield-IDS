# CyberShield-IDS - نظام كشف الاختراقات المتقدم

**نظام متقدم لكشف الاختراقات الشبكية مع واجهة رسومية ويب**

---

## 📖 المحتويات

- [المقدمة](#المقدمة)
- [المميزات](#المميزات)
- [المتطلبات](#المتطلبات)
- [التثبيت](#التثبيت)
- [الاستخدام](#الاستخدام)
- [البنية](#البنية)
- [الهجمات المكتشفة](#الهجمات-المكتشفة)
- [التوثيق](#التوثيق)

---

## 🎯 المقدمة

CyberShield-IDS هو نظام متقدم لكشف الاختراقات يجمع بين أحدث تقنيات الأمن السيبراني:

- ✅ **كشف التوقيعات** - اكتشاف الهجمات المعروفة
- ✅ **كشف الشذوذ** - اكتشاف السلوكيات المريبة
- ✅ **التعلم الآلي** - تصنيف ذكي للتهديدات
- ✅ **لوحة تحكم ويب** - مراقبة فورية

---

## ✨ المميزات الرئيسية

### 🔍 الكشف المتقدم

```
التقاط البيانات
    ↓
تحليل البروتوكولات
    ↓
مطابقة القواعس
    ↓
كشف الشذوذ
    ↓
التنبيهات الفورية
```

### 📊 لوحة التحكم

- عرض التنبيهات الفورية
- رسوم بيانية للمرور الشبكي
- إحصائيات الهجمات المكتشفة
- تصدير التقارير

### 🚀 الأداء

- معالجة سريعة للحزم
- دعم المعالجة المتعددة
- إدارة فعالة للذاكرة
- قابل للتوسع والتخصيص

---

## 📋 المتطلبات

### النظام
- Python 3.8 أو أحدث
- Linux أو macOS أو Windows (مع WSL)
- 4GB RAM (موصى به 8GB)
- واجهة شبكة نشطة

### المكتبات
```bash
Scapy          - التقاط الحزم
Flask          - واجهة الويب
SQLAlchemy     - قاعدة البيانات
Scikit-learn   - التعلم الآلي
Pandas         - معالجة البيانات
Plotly         - الرسوم البيانية
```

---

## 🔧 التثبيت

### 1. استنساخ المستودع

```bash
git clone https://github.com/nadlix/CyberShield-IDS.git
cd CyberShield-IDS
```

### 2. إنشاء بيئة افتراضية

```bash
python -m venv venv
source venv/bin/activate  # على Linux/macOS
# أو
venv\Scripts\activate  # على Windows
```

### 3. تثبيت المكتبات

```bash
pip install -r requirements.txt
```

### 4. إنشاء المجلدات المطلوبة

```bash
mkdir -p data logs exports backups models
```

---

## 🚀 الاستخدام

### تشغيل النظام الكامل

```bash
# مع صلاحيات المسؤول (مطلوب لالتقاط الحزم)
sudo python main.py  # على Linux/macOS
# أو
python main.py  # على Windows (من Command Prompt كمسؤول)
```

### تشغيل الكاشف من سطر الأوامر

```bash
sudo python core/packet_sniffer.py
```

### تشغيل لوحة التحكم

```bash
python dashboard/app.py
# ثم افتح: http://localhost:5000
```

---

## 📁 البنية

```
CyberShield-IDS/
├── core/
│   ├── __init__.py
│   ├── packet_sniffer.py       # التقاط البيانات
│   ├── protocol_analyzer.py    # تحليل البروتوكولات
│   ├── rules_engine.py         # محرك القواعس
│   └── alerts.py               # نظام التنبيهات
├── detection/
│   ├── signature_detection.py  # كشف التوقيعات
│   └── anomaly_detection.py    # كشف الشذوذ
├── dashboard/
│   ├── app.py                  # تطبيق Flask
│   ├── templates/              # قوالب HTML
│   └── static/                 # ملفات CSS/JS
├── database/
│   ├── models.py               # نماذج SQLAlchemy
│   └── queries.py              # عمليات قاعدة البيانات
├── config/
│   └── settings.py             # الإعدادات
├── rules/
│   └── attack_signatures.json  # قواعس الهجمات
├── main.py                     # نقطة البدء
├── requirements.txt            # المكتبات
└── README_AR.md               # هذا الملف
```

---

## 🚨 الهجمات المكتشفة

### 1️⃣ DDoS Attacks (هجمات الحرمان من الخدمة)
- اكتشاف تدفقات عالية من الحزم
- تحديد المصادر المتعددة
- حساب معدل الحزم

### 2️⃣ Port Scanning (مسح المنافذ)
- رصد المحاولات المتعددة للاتصال بمنافذ مختلفة
- تحديد أنواع المسح (SYN, XMAS)
- تنبيهات عند تجاوز الحد

### 3️⃣ SQL Injection (حقن SQL)
- كشف الأنماط المعروفة في البيانات
- الكشف عن الكلمات المفتاحية المريبة
- تحليل الحمولات (Payloads)

### 4️⃣ Brute Force Attacks (هجمات القوة الغاشمة)
- رصد محاولات الاتصال المتكررة
- تركيز على منافذ معينة (SSH 22)
- عد محاولات الفشل

### 5️⃣ Buffer Overflow (فيض المخزن)
- اكتشاف الحمولات الكبيرة غير العادية
- تحليل أحجام الحزم
- تنبيهات عند تجاوز الحدود

### 6️⃣ Malware Signatures (توقيعات البرامج الضارة)
- مطابقة البيانات مع قاعدة التوقيعات
- كشف الأنماط المعروفة
- تقييم الثقة (Confidence)

### 7️⃣ Unusual Traffic Patterns (أنماط غير عادية)
- المراقبة الإحصائية للمرور
- كشف الانحرافات عن الخط الأساسي
- استخدام Z-score

---

## 📊 مثال على الاستخدام

```python
# استيراد المكونات
from core.packet_sniffer import PacketSniffer
from core.protocol_analyzer import ProtocolAnalyzer
from core.rules_engine import RulesEngine
from core.alerts import AlertManager

# التهيئة
sniffer = PacketSniffer()
analyzer = ProtocolAnalyzer()
rules = RulesEngine()
alerts = AlertManager()

# بدء التقاط البيانات
sniffer.start()

# حلقة المراقبة
for i in range(100):
    packet = sniffer.get_next_packet()
    if packet:
        # تحليل الحزمة
        analysis = analyzer.analyze_packet(packet)
        
        # فحص القواعس
        alerts_list = rules.check_packet(analysis)
        
        # حفظ التنبيهات
        for alert in alerts_list:
            alerts.create_alert_from_rule(alert)

# التوقف
sniffer.stop()
```

---

## 🔐 الأمان

### التوصيات

1. **تشغيل كمسؤول**
   - النظام يحتاج صلاحيات عالية للتقاط الحزم
   
2. **قاعدة بيانات آمنة**
   - استخدم كلمات مرور قوية
   - قم بعمل نسخ احتياطية دورية

3. **الشبكة**
   - استخدم HTTPS للوحة التحكم
   - قيد الوصول بجدران حماية

4. **التحديثات**
   - حدّث المكتبات بانتظام
   - تابع التحديثات الأمنية

---

## 📈 الإحصائيات

```
الحزم المقبوضة:     15,234
التنبيهات الصادرة:   1,203
الهجمات المكتشفة:    45
  - DDoS:            12
  - Port Scan:       18
  - Brute Force:     8
  - SQL Injection:   7
```

---

## 🐛 استكشاف الأخطاء

### مشكلة: "Permission denied"

```bash
# الحل: استخدم sudo
sudo python main.py
```

### مشكلة: "No network interfaces found"

```bash
# تحقق من الواجهات
ip link show  # على Linux
ifconfig    # على macOS
```

### مشكلة: "Port 5000 already in use"

```bash
# غير المنفذ في config/settings.py
DASHBOARD_PORT = 5001
```

---

## 📚 الموارد الإضافية

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [OWASP Top 10](https://owasp.org/Top10/)
- [CyberShield GitHub](https://github.com/nadlix/CyberShield-IDS)

---

## 📄 الترخيص

هذا المشروع مرخص تحت **GPL-3.0**

---

## 👥 المساهمون

شكراً لكل من ساهم في تطوير هذا المشروع!

---

## 📞 التواصل والدعم

- 📧 البريد: nadanizar080@gmail.com
- 🐙 GitHub: [@nadlix](https://github.com/nadlix)
- 💬 Issues: [استفسارات المشروع](https://github.com/nadlix/CyberShield-IDS/issues)

---

## 🙏 شكر خاص

شكر خاص لمجتمع الأمن السيبراني على الدعم والإلهام!

---

**آخر تحديث:** يونيو 2026

**الحالة:** قيد التطوير النشط 🚀
