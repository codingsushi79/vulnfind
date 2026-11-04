# Labelled benchmark case (fake credentials).
AWS_KEY = "AKIAQ3EGRQFAKE7DEMO1"  # expect: SECRET-AWS-ACCESS-KEY
GITHUB = "ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"  # expect: SECRET-GITHUB-TOKEN
DB = "postgres://admin:Sup3rS3cretPw@db.internal:5432/prod"  # expect: SECRET-DB-URL
DOCS_DB = "postgres://user:hunter2pw@host:5432/app"  # safe
db_password = "Winter2026!"  # expect: SECRET-GENERIC
api_key = "your-api-key-here"  # safe
EXAMPLE = "AKIAIOSFODNN7EXAMPLE"  # safe
password = os.environ["DB_PASSWORD"]  # safe
