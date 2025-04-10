from typing import Callable
from functools import wraps
import time
import logging

logger = logging.getLogger(__name__)


def timing_decorator(func: Callable) -> Callable:
    """
    计时装饰器, 用于测量函数执行时间并在GUI中显示

    Args:
        func: 要计时的函数

    Returns:
        包装后的函数
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start_time
        logger.info(f"{func.__name__} completed in {elapsed:.3f} seconds")

        if (
            hasattr(args[0], "execution_time_label")
            and func.__name__ == "perform_encryption"
        ):
            args[0].execution_time_label.setText(f"执行加密时间: {elapsed:.3f} 秒")
        elif (
            hasattr(args[0], "decrypt_execution_time_label")
            and func.__name__ == "perform_decryption"
        ):
            args[0].decrypt_execution_time_label.setText(f"执行解密时间: {elapsed:.3f} 秒")

        return result

    return wrapper
