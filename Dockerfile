FROM python:3.12-slim

# hcxpcapngtool (from hcxtools) converts captures to Hashcat mode 22000.
RUN apt-get update \
    && apt-get install -y --no-install-recommends hcxtools \
    && rm -rf /var/lib/apt/lists/*

# Run as a non-root user (Hugging Face Spaces uses uid 1000).
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR /home/user/app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

COPY --chown=user . .

EXPOSE 7860

CMD ["streamlit", "run", "streamlit_app.py", \
     "--server.port=7860", "--server.address=0.0.0.0", \
     "--server.headless=true", "--browser.gatherUsageStats=false", \
     "--server.enableXsrfProtection=false", "--server.enableCORS=false"]
