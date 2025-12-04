from data import *
import time
import logging
import shlex
import json
import re
import statistics
from typing import Dict, List, Optional, Tuple, Generator
import itertools
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from http.client import RemoteDisconnected
from requests.exceptions import ConnectionError, Timeout, RequestException
import time
import logging
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, unquote
from enum import Enum


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

@dataclass
class BodyItem:
    """Track values and their placement in request body"""
    value: str
    placement: int


class InjectionType(Enum):
    """Types of NoSQL injections"""
    BLIND = "Blind NoSQL Injection"
    TIMED = "Timing based NoSQL Injection"
    ERROR = "Error based NoSQL Injection"
    GET_PARAM = "Get Parameter NoSQL Injection"

@dataclass
class InjectionObject:
    """Represents a discovered injection vulnerability"""
    injection_type: InjectionType
    attack_object: 'AttackObject'
    injectable_param: str
    injected_param: str
    injected_value: str
    prefix: str = ""
    suffix: str = ""

    def hash(self) -> str:
        """Generate unique hash for this injection"""
        serial = (
            f"{self.injection_type.value}"
            f"{self.attack_object.request.url}"
            f"{self.injectable_param}"
            f"{self.injected_param}"
            f"{self.injected_value}"
        )
        return hashlib.md5(serial.encode()).hexdigest()

    def __str__(self) -> str:
        return (
            f"Found {self.injection_type.value}:\n"
            f"\tURL: {self.attack_object.request.url}\n"
            f"\tparam: {self.injectable_param}\n"
            f"\tInjection: {self.injected_param}={self.injected_value}\n"
        )


@dataclass
class HTTPResponseObject:
    """HTTP response data"""
    url: str
    body: str
    headers: Dict[str, str]
    status_code: int

    def content_equals(self, other: 'HTTPResponseObject') -> bool:
        """Check if response content matches (ignoring URL)"""
        return (
            self.status_code == other.status_code and
            self.body == other.body
        )

    def deep_equals(self, other: 'HTTPResponseObject') -> bool:
        """Check if response fully matches including headers"""
        return self.content_equals(other) and self.headers == other.headers


@dataclass
class ScanOptions:
    """Configuration options for scanning"""
    target: str = ""
    request: str = ""
    proxy_input: str = ""
    user_agent_input: str = ""
    request_data: str = ""
    require_https: bool = False
    allow_insecure_certificates: bool = False

    def proxy(self) -> str:
        """Get proxy URL from input or environment"""
        import os
        return self.proxy_input or os.environ.get("HTTP_PROXY", "")

    def user_agent(self) -> str:
        """Get user agent string"""
        if self.user_agent_input:
            return self.user_agent_input
        return f"NoSQLInjector: {VERSION_NAME} v{VERSION}"

    


def create_robust_session(options) -> requests.Session:
    """Create a requests session with retry logic and proper configuration"""
    session = requests.Session()
    
    # Configure retry strategy with backoff
    retry_strategy = Retry(total=3, status_forcelist=[502, 503, 504])
    
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Apply common headers
    session.headers.update(COMMON_HEADERS)
    session.headers.update({"User-Agent": options.user_agent()})
    
    # Disable keep-alive for better compatibility
    session.keep_alive = False
    
    # SSL verification
    session.verify = not options.allow_insecure_certificates
    
    # Proxy configuration
    if options.proxy():
        session.proxies = {
            "http": options.proxy(),
            "https": options.proxy()
        }
    
    return session


def prepared_to_curl(method: str, url: str, headers: Dict[str,str], body: Optional[bytes]) -> str:
    """Return a curl command string to replicate this request for debugging."""
    cmd = ["curl", "-i", "-X", method]
    for k, v in headers.items():
        if k.lower() in ("content-length", "transfer-encoding", "connection", "expect"):
            continue
        cmd += ["-H", f"{k}: {v}"]
    if body:
        cmd += ["--data-binary", shlex.quote(body.decode('utf-8', errors='replace'))]
    cmd += [shlex.quote(url)]
    return " ".join(cmd)


def is_json(s: str) -> bool:
    """Check if string is valid JSON"""
    try:
        json.loads(s)
        return True
    except:
        return False


def flatten_json(json_str: str) -> List[str]:
    """Extract all keys and values from JSON"""
    result = []
    
    def process_value(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                result.append(key)
                result.append(json.dumps(value) if not isinstance(value, str) else value)
                process_value(value)
        elif isinstance(obj, list):
            result.append(json.dumps(obj))
            for item in obj:
                process_value(item)
    
    try:
        data = json.loads(json_str)
        process_value(data)
    except:
        pass
    
    return result

def js_injections(quote_type: str = "'") -> Dict[str, List[str]]:
    attacks = {}
    
    for prefix in JS_PREFIXES:
        for suffix in JS_SUFFIXES:
            for true_inj in JS_TRUE_STRINGS:
                t_inj = prefix + true_inj + suffix
                t_inj = t_inj.replace("'", quote_type)
                
                for false_inj in JS_FALSE_STRINGS:
                    f_inj = prefix + false_inj + suffix
                    f_inj = f_inj.replace("'", quote_type)
                    
                    if t_inj in attacks:
                        attacks[t_inj].append(f_inj)
                    else:
                        attacks[t_inj] = [f_inj]
    
    return attacks


def string_combinations(items: List[str]) -> Generator[List[str], None, None]:
    for r in range(1, len(items) + 1):
        for combo in itertools.combinations(items, r):
            yield list(combo)


def body_item_combinations(items: List[BodyItem]) -> Generator[List[BodyItem], None, None]:
    for r in range(1, len(items) + 1):
        for combo in itertools.combinations(items, r):
            yield list(combo)


def unique_injections(injections: List[InjectionObject]) -> List[InjectionObject]:
    seen = set()
    unique = []
    
    for inj in injections:
        h = inj.hash()
        if h not in seen:
            unique.append(inj)
            seen.add(h)
    
    return unique


def has_nosql_error(body: str) -> bool:
    """Check if response contains NoSQL error"""
    mongo_errors = search_error(body, MONGO_ERROR_STRINGS)
    mongoose_errors = search_error(body, MONGOOSE_ERROR_STRINGS)
    return mongo_errors or mongoose_errors


def has_js_error(body: str) -> bool:
    """Check if response contains JavaScript error"""
    return search_error(body, JS_SYNTAX_ERROR_STRINGS)


def search_error(body: str, error_list: List[str]) -> bool:
    """Search for error patterns in response body"""
    for pattern in error_list:
        if re.search(pattern, body):
            return True
    return False


def error_based_injection_test(att: AttackObject) -> List[InjectionObject]:
    """Run error-based injection tests"""
    injectables = []
    injectables.extend(inject_special_chars_into_query(att))
    injectables.extend(inject_special_chars_into_body(att))
    return injectables


def inject_special_chars_into_query(att: AttackObject) -> List[InjectionObject]:
    """Inject special characters into query parameters"""
    injectables = iterate_get_injections(att, MONGO_SPECIAL_CHARACTERS, False)
    injectables.extend(iterate_get_injections(att, MONGO_SPECIAL_KEY_CHARACTERS, True))
    return injectables


def inject_special_chars_into_body(att: AttackObject) -> List[InjectionObject]:
    """Inject special characters into request body"""
    injectables = iterate_body_injections(att, MONGO_SPECIAL_CHARACTERS, False)
    injectables.extend(iterate_body_injections(att, MONGO_SPECIAL_KEY_CHARACTERS, True))
    injectables.extend(iterate_body_injections(att, MONGO_JSON_ERROR_ATTACKS, True))
    return injectables


def iterate_body_injections(att: AttackObject, injection_list: List[str], inject_keys: bool) -> List[InjectionObject]:
    """Iterate through body injections"""
    injectables = []
    for injection in injection_list:
        for pattern in att.body_values:
            att.replace_body_object(pattern.value, injection, inject_keys, pattern.placement)
            res = att.send()
            if has_nosql_error(res.body):
                injectable = InjectionObject(
                    injection_type=InjectionType.ERROR,
                    attack_object=att,
                    injectable_param=pattern.value,
                    injected_param=injection,
                    injected_value=""
                )
                injectables.append(injectable)
            att.restore_body()
    return injectables


def iterate_get_injections(att: AttackObject, injection_list: List[str], inject_keys: bool) -> List[InjectionObject]:
    """Iterate through GET parameter injections"""
    injectables = []
    for injection in injection_list:
        for key, value in att.query_params().items():
            injected_value = value
            injected_key = key
            
            if inject_keys:
                att.replace_query_param(key, key + injection, value)
                injected_key = key + injection
            else:
                att.set_query_param(key, injection)
                injected_value = injection
            
            res = att.send()
            if res.status_code == 0:
                logging.warning(f"Skipping failed request for {key}")
                continue
            if has_nosql_error(res.body):
                injectable = InjectionObject(
                    injection_type=InjectionType.ERROR,
                    attack_object=att,
                    injectable_param=key,
                    injected_param=injected_key,
                    injected_value=injected_value
                )
                injectables.append(injectable)
            
            # Reset to default
            if inject_keys:
                att.replace_query_param(key + injection, key, value)
            else:
                att.set_query_param(key, value)
    
    return injectables


# ============================================================================
# BLIND BOOLEAN SCANNER (boolean_blind_scanner.go)
# ============================================================================

def blind_boolean_injection_test(att: AttackObject) -> List[InjectionObject]:
    """Run blind boolean injection tests"""
    injectables = []
    injectables.extend(iterate_regex_get_boolean_injections(att))
    injectables.extend(iterate_regex_post_boolean_injections(att))
    injectables.extend(iterate_js_get_boolean_injections(att))
    injectables.extend(iterate_js_post_boolean_injections(att))
    injectables.extend(iterate_object_injections(att))
    return injectables


def is_blind_injectable(baseline: HTTPResponseObject, true_res: HTTPResponseObject, 
                       false_res: HTTPResponseObject) -> bool:
    """Check if responses indicate blind injection"""
    if has_nosql_error(false_res.body) or has_nosql_error(true_res.body):
        return False
    if has_js_error(false_res.body) or has_js_error(true_res.body):
        return False
    if baseline.content_equals(true_res) and baseline.content_equals(false_res):
        return False
    if baseline.content_equals(true_res) and not baseline.content_equals(false_res):
        return True
    if not baseline.content_equals(true_res) and baseline.content_equals(false_res):
        return True
    return False


def run_injection(baseline: AttackObject, true_object: AttackObject, false_object: AttackObject,
                 key: str, injected_key: str, true_val: str, false_val: str) -> Tuple[InjectionObject, bool]:
    """Run and compare three requests to test for injection"""
    baseline_res = baseline.send()
    true_res = true_object.send()
    false_res = false_object.send()
    
    injectable = InjectionObject(
        injection_type=InjectionType.BLIND,
        attack_object=baseline,
        injectable_param=key,
        injected_param=injected_key,
        injected_value=""
    )
    
    if is_blind_injectable(baseline_res, true_res, false_res):
        injectable.injected_value = f"true: {true_val}, false: {false_val}"
        return injectable, True
    
    return injectable, False


def iterate_regex_get_boolean_injections(att: AttackObject) -> List[InjectionObject]:
    """Test regex injections in GET parameters"""
    injectables = []
    true_regex = ".*"
    false_regex = "a^"
    
    original_params = att.query_params()
    keys = list(original_params.keys())
    
    baseline = att.copy()
    baseline2 = att.copy()
    
    # Try with empty parameters
    for key in keys:
        baseline2.set_query_param(key, "")
    
    baseline_res2 = baseline2.send()
    if not has_js_error(baseline_res2.body) and not has_nosql_error(baseline_res2.body):
        baseline = baseline2
    
    for keylist in string_combinations(keys):
        true_obj = baseline.copy()
        for key in keylist:
            injected_key = key + "[$regex]"
            true_obj.replace_query_param(key, injected_key, true_regex)
        
        for key in keylist:
            injected_key = key + "[$regex]"
            false_obj = true_obj.copy()
            false_obj.set_query_param(injected_key, false_regex)
            
            injectable, success = run_injection(baseline, true_obj, false_obj, key, 
                                               injected_key, true_regex, false_regex)
            if success:
                injectables.append(injectable)
    
    return unique_injections(injectables)


def iterate_regex_post_boolean_injections(att: AttackObject) -> List[InjectionObject]:
    """Test regex injections in POST body"""
    injectables = []
    baseline = att
    true_regex = '{"$regex": ".*"}'
    false_regex = '{"$regex": "a^"}'
    inject_keys = True
    
    for keylist in body_item_combinations(att.body_values):
        true_obj = baseline.copy()
        
        for pattern in keylist:
            true_obj.replace_body_object(pattern.value, true_regex, inject_keys, pattern.placement)
        
        false_obj = true_obj.copy()
        for i, pattern in enumerate(keylist):
            false_obj.replace_body_object(true_regex, false_regex, inject_keys, i)
            
            injectable, success = run_injection(baseline, true_obj, false_obj, pattern.value,
                                               pattern.value, true_regex, false_regex)
            if success:
                injectables.append(injectable)
            
            false_obj.replace_body_object(false_regex, true_regex, inject_keys, -1)
    
    return unique_injections(injectables)


def iterate_js_get_boolean_injections(att: AttackObject) -> List[InjectionObject]:
    """Test JavaScript injections in GET parameters"""
    injectables = []
    original_params = att.query_params()
    keys = list(original_params.keys())
    
    for quote_type in ["'", '"']:
        injections = js_injections(quote_type)
        for keylist in string_combinations(keys):
            for true_js, false_injections in injections.items():
                true_obj = att.copy()
                for key in keylist:
                    true_obj.set_query_param(key, original_params[key] + true_js)
                
                false_obj = true_obj.copy()
                for key in keylist:
                    for false_js in false_injections:
                        injection = original_params[key] + false_js
                        false_obj.set_query_param(key, injection)
                        
                        injectable, success = run_injection(att, true_obj, false_obj, key, key,
                                                           original_params[key] + true_js, injection)
                        if success:
                            injectables.append(injectable)
                        
                        false_obj.set_query_param(key, original_params[key])
    
    return unique_injections(injectables)


def iterate_js_post_boolean_injections(att: AttackObject) -> List[InjectionObject]:
    """Test JavaScript injections in POST body"""
    injectables = []
    
    for quote_type in ["'"]:
        injections = js_injections(quote_type)
        for keylist in body_item_combinations(att.body_values):
            for true_js, false_injections in injections.items():
                true_obj = att.copy()
                for key in keylist:
                    injection = f'"{key.value}{true_js}"'
                    true_obj.replace_body_object(key.value, injection, False, key.placement)
                
                for i, key in enumerate(keylist):
                    for false_js in false_injections:
                        false_obj = true_obj.copy()
                        injection = f'"{key.value}{false_js}"'
                        false_obj.replace_body_object(key.value + true_js, injection, False, i)
                        
                        injectable, success = run_injection(att, true_obj, false_obj, key.value,
                                                           key.value, key.value + true_js, injection)
                        if success:
                            injectables.append(injectable)
    
    return unique_injections(injectables)


def iterate_object_injections(att: AttackObject) -> List[InjectionObject]:
    """Test object injections"""
    injectables = []
    
    true_request = att.copy()
    false_request = att.copy()
    
    for true_object in OBJECT_INJECTIONS_TRUE:
        true_request.set_body(true_object)
        for false_object in OBJECT_INJECTIONS_FALSE:
            false_request.set_body(false_object)
            
            injectable, success = run_injection(att, true_request, false_request, 
                                               "Body", "", true_object, false_object)
            if success:
                injectables.append(injectable)
    
    return unique_injections(injectables)


# ============================================================================
# GET INJECTION SCANNER (get_injection_scanner.go)
# ============================================================================

def get_injection_test(att: AttackObject) -> List[InjectionObject]:
    """Test GET parameter injections"""
    return inject_mongo_characters(att)


def injectables_contains_param(injectables: List[InjectionObject], param: str) -> bool:
    """Check if parameter already found"""
    return any(i.injectable_param == param for i in injectables)


def inject_mongo_characters(att: AttackObject) -> List[InjectionObject]:
    """Try MongoDB operator injections in GET parameters"""
    baseline = att.copy()
    baseline_res = baseline.send()
    
    truthy_values = [["[$ne]", ""], ["[$ne]", "a"]]
    injectables = []
    keys = list(att.query_params().keys())
    
    for combo in string_combinations(keys):
        for injection in MONGO_GET_INJECTION:
            for param in combo:
                for truthy_injection in truthy_values:
                    if injectables_contains_param(injectables, param):
                        continue
                    
                    injection_obj = att.copy()
                    
                    # Set other keys to truthy
                    for p2 in combo:
                        if p2 == param:
                            continue
                        injection_obj.replace_query_param(p2, p2 + truthy_injection[0], 
                                                         truthy_injection[1])
                    
                    test_values = ["", "a", "z", "0", "9", att.query_params()[param]]
                    for injected_value in test_values:
                        injection_obj.replace_query_param(param, param + injection, injected_value)
                        res = injection_obj.send()
                        
                        if not baseline_res.content_equals(res):
                            injectable = InjectionObject(
                                injection_type=InjectionType.GET_PARAM,
                                attack_object=injection_obj,
                                injectable_param=param,
                                injected_param=param + injection,
                                injected_value=injected_value
                            )
                            injectables.append(injectable)
                            break
                        
                        injection_obj.replace_query_param(param + injection, param, injected_value)
    
    return injectables


# ============================================================================
# TIMING SCANNER (timing_scanner.go)
# ============================================================================

SLEEP_TIME_MS = 500


def timing_injection_test(att: AttackObject) -> List[InjectionObject]:
    """Run timing-based injection tests"""
    att.ignore_cache = True
    injectables = []
    injectables.extend(iterate_timing_get_injections(att))
    injectables.extend(iterate_post_timing_injections(att))
    injectables.extend(iterate_post_object_injections(att))
    att.ignore_cache = False
    return injectables


def measure_request(request: AttackObject) -> float:
    """Measure request time in seconds"""
    start = time.time()
    request.send()
    return time.time() - start


def baseline(att: AttackObject) -> List[float]:
    """Get baseline timings"""
    baseline_times = []
    for _ in range(3):
        baseline_times.append(measure_request(att))
    return baseline_times


def is_timing_injectable(baselines: List[float], injection_time: float) -> bool:
    """Check if timing indicates injection"""
    mean = statistics.mean(baselines)
    std_dev = statistics.stdev(baselines)
    
    threshold = SLEEP_TIME_MS / 1000.0
    if injection_time > threshold and injection_time > (mean + 2 * std_dev):
        return True
    return False


def iterate_timing_get_injections(att: AttackObject) -> List[InjectionObject]:
    """Test timing injections in GET parameters"""
    baseline_times = baseline(att)
    injectables = []
    params = att.query_params()
    
    for key in params:
        for prefix in JS_PREFIXES:
            for suffix in JS_SUFFIXES:
                for t_injection in js_timing_strings(JS_TIMING_STRINGS_RAW, SLEEP_TIME_MS):
                    for keep_val in ["", params[key]]:
                        attack_obj = att.copy()
                        attack_string = keep_val + prefix + t_injection + suffix
                        attack_obj.set_query_param(key, attack_string)
                        timing = measure_request(attack_obj)
                        
                        if is_timing_injectable(baseline_times, timing):
                            injectable = InjectionObject(
                                injection_type=InjectionType.TIMED,
                                attack_object=attack_obj,
                                injectable_param=key,
                                injected_param=keep_val,
                                injected_value=attack_string
                            )
                            injectables.append(injectable)
    
    return unique_injections(injectables)


def iterate_post_timing_injections(att: AttackObject) -> List[InjectionObject]:
    """Test timing injections in POST body"""
    baseline_times = baseline(att)
    injectables = []
    
    for body_value in att.body_values:
        for prefix in JS_PREFIXES:
            for suffix in JS_SUFFIXES:
                for t_injection in js_timing_strings(JS_TIMING_STRINGS_RAW, SLEEP_TIME_MS):
                    for keep_val in ["", body_value.value]:
                        for wrap_quote in ["", '"']:
                            attack_obj = att.copy()
                            attack_string = wrap_quote + keep_val + prefix + t_injection + suffix + wrap_quote
                            attack_obj.replace_body_object(body_value.value, attack_string, 
                                                          False, body_value.placement)
                            timing = measure_request(attack_obj)
                            
                            if is_timing_injectable(baseline_times, timing):
                                injectable = InjectionObject(
                                    injection_type=InjectionType.TIMED,
                                    attack_object=attack_obj,
                                    injectable_param=body_value.value,
                                    injected_param=body_value.value,
                                    injected_value=attack_string
                                )
                                injectables.append(injectable)
    
    return unique_injections(injectables)


def iterate_post_object_injections(att: AttackObject) -> List[InjectionObject]:
    """Test timing injections with full object replacement"""
    baseline_times = baseline(att)
    injectables = []
    
    timed_request = att.copy()
    for t_injection in js_timing_strings(JS_TIMING_OBJECT_INJECTIONS_RAW, SLEEP_TIME_MS):
        timed_request.set_body(t_injection)
        timing = measure_request(timed_request)
        
        if is_timing_injectable(baseline_times, timing):
            injectable = InjectionObject(
                injection_type=InjectionType.TIMED,
                attack_object=timed_request,
                injectable_param="Whole Body",
                injected_param="Whole Body",
                injected_value=t_injection
            )
            injectables.append(injectable)
    
    return unique_injections(injectables)



def scan_all(att: AttackObject) -> Dict[str, List[InjectionObject]]:
    """Run all injection tests"""
    results = {
        "error": error_based_injection_test(att),
        "blind_boolean": blind_boolean_injection_test(att),
        "get_param": get_injection_test(att),
        "timing": timing_injection_test(att)
    }
    return results

