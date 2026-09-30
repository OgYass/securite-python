FROM python:3.12-slim

WORKDIR /app 

RUN pip install poetry

COPY . .

RUN poetry install

CMD ["poetry", "run", "tp1"]

