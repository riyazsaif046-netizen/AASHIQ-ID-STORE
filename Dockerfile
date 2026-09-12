FROM python:3.12-slim
WORKDIR /app
COPY . /app
ENV PORT=8080
EXPOSE 8080
CMD ["python", "ticket_server.py"]
