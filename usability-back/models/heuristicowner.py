from utils.db import db


class HeuristicOwner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    checklists = db.relationship('HeuristicCheckList', backref='owner', lazy=True)
