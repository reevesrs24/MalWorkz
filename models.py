import torch
import numpy as np
import lightgbm as lgb
import torch.nn.functional as F

from MalConv import MalConv
from ember import predict_sample


MALCONV_MODEL_PATH = "models/malconv/malconv.checkpoint"
NONNEG_MODEL_PATH = "models/nonneg/nonneg.checkpoint"
EMBER_MODEL_PATH = "models/ember/ember_model.txt"


class MalConvModel(object):
    def __init__(self, model_path, thresh=0.5, name="malconv"):
        self.model = MalConv(channels=256, window_size=512, embd_size=8).train()
        weights = torch.load(model_path, map_location="cpu")
        self.model.load_state_dict(weights["model_state_dict"])
        self.thresh = thresh
        self.__name__ = name

    def predict(self, bytez):
        _inp = torch.from_numpy(np.frombuffer(bytez, dtype=np.uint8)[np.newaxis, :])
        with torch.no_grad():
            outputs = F.softmax(self.model(_inp), dim=-1)

        return outputs.detach().numpy()[0, 1]


class EmberModel(object):
    # ember_threshold = 0.8336 # resulting in 1% FPR
    def __init__(self, model_path=EMBER_MODEL_PATH, thresh=0.8336, name="ember"):
        # load lightgbm model
        self.model = lgb.Booster(model_file=model_path)
        self.thresh = thresh
        self.__name__ = "ember"

    def predict(self, bytez):
        return predict_sample(self.model, bytez)
