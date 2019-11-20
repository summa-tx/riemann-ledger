pipenv run flake8 \
    --ignore=W503,W504 \
    --exclude ledger/tests/ \
    ledger && \
pipenv run mypy \
    ledger/ \
    --disallow-untyped-defs \
    --strict-equality \
    --show-error-codes \
    --warn-return-any \
    --ignore-missing-imports && \
pipenv run coverage erase && \
pipenv run pytest \
    ledger/ \
    -q \
    --cov-config .coveragerc \
    --cov-report= \
    --cov && \
pipenv run coverage report && \
pipenv run coverage html
