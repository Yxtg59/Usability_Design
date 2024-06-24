from utils.db import db
class HeuristicProblems(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('heuristic_owner.id'), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    heuristic_description_id = db.Column(db.Integer, db.ForeignKey('heuristic_descriptions.id'), nullable=False)

    def __init__(self, problemownerid, problemname, problemdescriptionid):
        self.owner_id = problemownerid
        self.name = problemname
        self.heuristic_description_id = problemdescriptionid