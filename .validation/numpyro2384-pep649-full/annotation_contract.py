import json,sys
from functools import partial
from typing import TYPE_CHECKING
sys.path.insert(0,sys.argv[1])
import numpyro
import numpyro.distributions as dist
from numpyro.infer.util import initialize_model,find_valid_initial_params
from jax import random
if TYPE_CHECKING:
    from unavailable_annotation_only_module import Site

def strategy(site: Site | None = None):  # noqa: F821
    if site is None:return partial(strategy)
    return 0.0

def model():numpyro.sample("x",dist.Normal())
rows=[]
for fn in (initialize_model,find_valid_initial_params):
    try:
        info=fn(random.key(0),model,init_strategy=strategy)[0]
    except NameError as exc:
        assert sys.argv[2]=="baseline" and "Site" in str(exc)
        rows.append({"api":fn.__name__,"expected_baseline_error":repr(exc)})
    else:
        assert sys.argv[2]=="candidate" and float(info[0]["x"])==0.0
        rows.append({"api":fn.__name__,"x":float(info[0]["x"])})
print(json.dumps(rows))
