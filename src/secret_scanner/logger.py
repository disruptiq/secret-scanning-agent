import logging
import multiprocessing
from logging.handlers import QueueHandler, QueueListener
from queue import Queue

# Set up asynchronous logging
log_queue = multiprocessing.Queue()

# Create a console handler for the queue listener
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

# Create the queue listener
listener = QueueListener(log_queue, console_handler)
listener.start()

# Disable default logging and set up queue-based logging
logging.getLogger().handlers.clear()
logging.getLogger().addHandler(QueueHandler(log_queue))
logging.getLogger().setLevel(logging.INFO)

# Create a logger for this module
logger = logging.getLogger(__name__)
