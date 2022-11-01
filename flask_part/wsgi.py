from flask import Flask

import app_config

app = Flask(__name__)
app.config.from_object(app_config)