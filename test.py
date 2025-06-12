import os
from dotenv import load_dotenv
load_dotenv()


print(os.environ.get('EMAIL_HOST_USER')) 
print(os.environ.get('EMAIL_HOST_PASSWORD'))
