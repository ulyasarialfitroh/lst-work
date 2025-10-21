from typing import List, Any, Generator, Iterable

def flatten_list(nested_list: Iterable[Any]) -> List[Any]:
    """
    Flattens a list containing arbitrarily nested lists and other iterables.

    This function recursively iterates through the elements of the input iterable.
    If an element is an iterable (and not a string), it recursively flattens it.
    Otherwise, it yields the element.

    Args:
        nested_list: An iterable (e.g., list, tuple) that may contain other
                     iterables as elements.

    Returns:
        A new list containing all elements from the nested structure in a
        single dimension.
    
    Example:
        >>> flatten_list([1, [2, 3], 4, ('a', [5.0])])
        [1, 2, 3, 4, 'a', 5.0]
    """
    def _flatten_generator(items: Iterable[Any]) -> Generator[Any, None, None]:
        for item in items:
            if isinstance(item, Iterable) and not isinstance(item, (str, bytes)):
                yield from _flatten_generator(item)
            else:
                yield item

    return list(_flatten_generator(nested_list))
