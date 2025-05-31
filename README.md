# AIronSafe Deployment Guide (AWS EC2 + Local)

## 🛠️ Requirements

- An Amazon Web Services (AWS) account  
- Git  
- Docker & Docker Compose  
- (Optional) NGINX (for reverse proxy and HTTPS support)  

---

## ☁️ Deployment on AWS EC2

### 1. Create an AWS Account

Go to [https://aws.amazon.com](https://aws.amazon.com) and create a free or paid account.

---

### 2. Launch an EC2 Instance

- Log into the AWS Console.  
- Navigate to **EC2 > Launch Instance**.  
- Select **Amazon Linux 2** as the operating system.  
- Choose an instance type (e.g., `t2.medium` recommended).  
- Configure the **Security Group** to allow:
  - TCP 22 (SSH)
  - TCP 80 (HTTP)
  - TCP 443 (HTTPS) *(optional)*
  - TCP 3000 (direct access to frontend)  
- Create or select a key pair and download the `.pem` file.

---

### 3. Connect via SSH

```bash
ssh -i "your-key.pem" ec2-user@<EC2_PUBLIC_IP>
```

---

### 4. Install Docker

```bash
sudo yum update -y
sudo yum install docker -y
sudo service docker start
sudo usermod -a -G docker ec2-user
```

> **Note:** You may need to log out and log back in for the Docker group permission to take effect.

---

### 5. Install Docker Compose

```bash
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
docker-compose --version
```

---

### 6. (Optional) Install and Configure NGINX

NGINX can be used to route traffic from port 80 to 3000 or to set up HTTPS.

#### Install NGINX:

```bash
sudo amazon-linux-extras install nginx1 -y
sudo systemctl enable nginx
sudo systemctl start nginx
```

#### Configure as a reverse proxy:

```bash
sudo nano /etc/nginx/nginx.conf
```

Inside the `server` block, add:

```nginx
location / {
    proxy_pass http://localhost:3000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection 'upgrade';
    proxy_set_header Host $host;
    proxy_cache_bypass $http_upgrade;
}
```

Then test and restart:

```bash
sudo nginx -t
sudo systemctl restart nginx
```

---

### 7. Clone and Run AIronSafe

```bash
git clone https://github.com/your-username/AIronSafe.git
cd AIronSafe
docker-compose up --build
```

---

### 8. Access the Application

- If using NGINX: `http://<EC2_PUBLIC_IP>`
- If not using NGINX: `http://<EC2_PUBLIC_IP>:3000`

---

## 💻 Local Deployment

### 1. Install Docker and Docker Compose

Download Docker Desktop from [https://www.docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop) and install it.

---

### 2. Clone the Repository

```bash
git clone https://github.com/your-username/AIronSafe.git
cd AIronSafe
```

---

### 3. Build and Run the Project

```bash
docker-compose up --build
```

---

### 4. Open in Browser

Go to: [http://localhost:3000](http://localhost:3000)

---

## 📌 Notes

- Don’t forget to include your OpenAI API key in a `.env` file before running the platform.
- On AWS, ensure required ports are open in the Security Group settings.
- For HTTPS setup on EC2, you can integrate Let's Encrypt certificates via NGINX.
