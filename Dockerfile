FROM python:3.12-slim
# INSTALL_ML=1 adds CPU PyTorch + sentence-transformers for real MiniLM embeddings (free, ~1 GB bigger image).
# Default is the dependency-free hashing embedder.
ARG INSTALL_ML=0
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && if [ "$INSTALL_ML" = "1" ]; then \
      pip install --no-cache-dir --extra-index-url https://download.pytorch.org/whl/cpu torch \
      && pip install --no-cache-dir -r requirements-ml.txt; \
    fi
COPY . .
RUN useradd -m aegis && chown -R aegis /srv
USER aegis
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=20 CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/health')"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
