from app import app
import logging
import ecs_logging
from concurrent_log_handler import ConcurrentRotatingFileHandler
#from logging.handlers import RotatingFileHandler

#file_handler = RotatingFileHandler("app.json", maxBytes=5000, backupCount = 100)
file_handler = ConcurrentRotatingFileHandler("logs/app.json", "a", maxBytes=50*1024, backupCount=20) 
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(ecs_logging.StdlibFormatter())
app.logger.addHandler(file_handler)

app.run(host='0.0.0.0', debug=False)