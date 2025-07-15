# RAG Security Scanner Makefile

.PHONY: help install demo quick full data function context reports clean docker-build docker-run

help:
	@echo "🚀 RAG Security Scanner"
	@echo "======================"
	@echo "Available commands:"
	@echo "  make install      - Install dependencies"
	@echo "  make demo         - Demo scan"
	@echo "  make quick        - Quick scan (prompt injection only)"
	@echo "  make full         - Full scan"
	@echo "  make data         - Data leakage scan"
	@echo "  make function     - Function abuse scan"
	@echo "  make context      - Context manipulation scan"
	@echo "  make reports      - Show all reports"
	@echo "  make clean        - Clean reports"
	@echo "  make docker-build - Build Docker image"
	@echo "  make docker-run   - Run with Docker"

install:
	@echo "📦 Installing dependencies..."
	pip install -r requirements.txt

demo:
	@echo "🔍 Demo scan..."
	python src/rag_scanner.py --demo --format html

quick:
	@echo "⚡ Quick scan..."
	python src/rag_scanner.py --scan-type prompt --format json --delay 0.5

full:
	@echo "🔍 Full scan..."
	python src/rag_scanner.py --scan-type full --format html --delay 1.0

data:
	@echo "🔍 Data leakage scan..."
	python src/rag_scanner.py --scan-type data --format json --delay 0.7

function:
	@echo "🔍 Function abuse scan..."
	python src/rag_scanner.py --scan-type function --format json --delay 0.7

context:
	@echo "🔍 Context manipulation scan..."
	python src/rag_scanner.py --scan-type context --format json --delay 0.7

reports:
	@echo "📄 Generated reports:"
	@find reports -name "*.json" -o -name "*.html" 2>/dev/null || echo "No reports found"

clean:
	@echo "🧹 Cleaning reports..."
	rm -rf reports/
	rm -f *_report.json *_report.html

docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t rag-security-scanner .

docker-run:
	@echo "🐳 Running with Docker..."
	docker run -it --rm rag-security-scanner --demo