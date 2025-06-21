release: sh -c "docker-compose build && docker-compose run --rm web python manage.py makemigrations && docker-compose run --rm web python manage.py migrate"
web: docker-compose up --build
