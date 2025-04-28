import datetime
import logging
import os

# Create datetime for log file
today_ = datetime.datetime.today()
today = today_.strftime('%Y-%m-%d_%H_%M_%S')

# CSV file to ingest
ir_main_file = os.path.join(os.environ['USERPROFILE'], 'Desktop','IR', 'f.csv')

# Incident Response output directory
ir_output_file = os.path.join(os.environ['USERPROFILE'], 'Desktop', 'IR', 'IR_' + str(today)  + '.xlsx')

# Create IR log file with datetime value
ir_logfile = os.path.join(os.environ['USERPROFILE'], 'Desktop', 'Logs', 'IR_Algo_' + str(today) + '.log')

# Logger settings
ir_logger = logging.getLogger(__name__)
ir_logger.setLevel(logging.INFO)
formatter_ir = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
file_handler_ir = logging.FileHandler(ir_logfile)
file_handler_ir.setFormatter(formatter_ir)
ir_logger.addHandler(file_handler_ir)
