.PHONY: up down demo test test-int lint eval eval-http datasets tune local-start local-stop

up:            ## build and start gateway, mock-llm, postgres, redis
	docker compose up --build -d --wait
down:
	docker compose down -v
demo:          ## full scripted walkthrough (starts the stack if needed)
	bash scripts/demo.sh
test:          ## unit + API tests (no services needed), coverage gate 80%
	pytest --ignore=tests/test_integration.py --cov=app --cov=mock_llm --cov-fail-under=80 -p no:logging
test-int:      ## integration tests against real Postgres+Redis (docker compose up postgres redis first, or set the URLs)
	AEGIS_TEST_DATABASE_URL=$${AEGIS_TEST_DATABASE_URL:-postgresql+psycopg://aegis:aegis@localhost:5432/aegis_test} \
	AEGIS_TEST_REDIS_URL=$${AEGIS_TEST_REDIS_URL:-redis://localhost:6379/1} pytest tests/test_integration.py -p no:logging
lint:
	ruff check .
datasets:      ## regenerate eval/attacks.jsonl and eval/benign.jsonl
	python eval/build_datasets.py
tune:          ## fit thresholds on the TUNING split only
	python eval/run_eval.py --tune
eval:          ## in-process evaluation (all modes) -> eval/results.md, eval/results.json; fails on regression
	python eval/run_eval.py --check
eval-http:     ## also run through the live gateway and measure added latency (stack must be up)
	python eval/run_eval.py --http http://localhost:8000 --upstream http://localhost:9000 --check
local-start:   ## run without Docker (needs local Postgres+pgvector and Redis)
	bash scripts/run_local.sh start
local-stop:
	bash scripts/run_local.sh stop
