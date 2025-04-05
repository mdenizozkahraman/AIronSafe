FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# BeautifulSoup, ReportLab ve diğer gerekli kütüphaneleri yükle
RUN pip install --no-cache-dir beautifulsoup4 reportlab requests bcrypt flask-bcrypt

COPY . .

ENV PYTHONPATH=/app

EXPOSE 5000

CMD ["python", "app.py"]
