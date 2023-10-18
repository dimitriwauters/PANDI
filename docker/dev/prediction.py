import pickle
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from create_features import Features

def classify(name):
    features = Features("/output").generate_features(name)
    features.pop("name")
    features = pd.DataFrame(features, index=[0])
    model = pickle.load(open("/addon/wild_dynamic_GBDT.pickle","rb"))
    return model.predict(features)[0]
