FROM python:3.14-slim

WORKDIR /app

RUN pip install poetry

COPY . .

CMD ["poetry", "run", "tp1"]
