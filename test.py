from django.conf import settings
import os
from dotenv import load_dotenv
load_dotenv()


print(settings.SECRET_KEY)
print(os.environ.get('SECRET_KEY')) 
print(os.environ.get('EMAIL_HOST_PASSWORD'))
