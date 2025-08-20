import pprint
import sys
import os
import pickle
from collections.abc import Iterable


class SCARPickles(dict):

    @classmethod
    def loader(cls,file):
        """
        Load and return a pickled object from the given file path, or False if the file does not exist.
        
        Parameters:
            file (str | os.PathLike): Path to the pickle file to load.
        
        Returns:
            object | bool: The unpickled Python object if the file exists; otherwise False.
        """
        if os.path.isfile(file):
            with open(file, "rb") as f:
                return pickle.load(f)
        else:
            return False

    def __init__(self, pickle_name, data = None):
        """
        Initialize the SCARPickles dict, optionally merging in existing persisted data and provided initial data, then persist the result.
        
        Parameters:
            pickle_name (str): Base name (without extension) of the pickle file stored under `<application_path>/data/{pickle_name}.pkl`.
            data (Optional[Mapping]): Optional mapping of initial keys/values to merge into the instance; ignored if not iterable.
        
        Behavior:
            - Sets 'application_path' to the frozen application's bundle path (sys._MEIPASS) when running in a frozen environment, otherwise to the directory containing this module.
            - Stores the supplied pickle_name under the 'pickle_name' key.
            - Attempts to load an existing pickle file at `<application_path>/data/{pickle_name}.pkl`; if present and iterable, merges its keys/values into the new instance.
            - If `data` is provided and iterable, merges its keys/values into the instance, potentially overriding values from the existing pickle.
            - Calls self.save() to persist the merged dictionary to the pickle file.
        
        Notes:
            - `data` must be an iterable mapping (e.g., dict) to be merged; non-iterable values are ignored.
            - This constructor has the side effect of writing the pickle file via save().
        """
        dict.__init__(self)
        
        if getattr(sys, 'frozen', False):
            self['application_path'] = sys._MEIPASS
        else:
            self['application_path'] = os.path.dirname(os.path.abspath(__file__))
        
        self['pickle_name'] = pickle_name
        
        #see if the pickle already exists
        existing_path = os.path.join( self['application_path'], 'data', self['pickle_name'] + '.pkl' )
        existing_pickle = SCARPickles.loader( existing_path )
        
        if existing_pickle and isinstance(existing_pickle, Iterable):
            for key in existing_pickle.keys():
                self[key] = existing_pickle[key]
        
        if data and isinstance(data, Iterable):
            for key in data.keys():
                self[key] = data[key]

        self.save()
    
    def dump(self):
        """
        Return a plain dict copy of the current SCARPickles contents.
        
        Creates and returns a new dictionary mapping each key in this SCARPickles instance to its corresponding value. The returned dict is a shallow copy; mutating it does not affect the SCARPickles instance.
        Returns:
            dict: A plain Python dictionary containing the same key-value pairs as this SCARPickles.
        """
        results = {}
        for key in self.keys():
            results[key] = self[key]
        return results
    
    def list(self):
        """
        Return a list of the dictionary's keys in insertion order.
        
        Returns:
            list: A new list containing the current keys from this mapping, in the same order they appear in the dictionary.
        """
        return list(self.keys())
        
    def get(self, key, default=None): 
        """
        Return the value for `key` if present, otherwise return `default`.
        
        Parameters:
            key: The dictionary key to look up.
            default: Value returned when `key` is not found (defaults to None).
        
        Returns:
            The value associated with `key` if it exists in the mapping; otherwise `default`.
        """
        return self[key] if key in self else default
        
    #def get(self, key, default=None):
    #    if key in self.keys():
    #        return self[key]
    #    else:
    #        return None

    def set(self, key, value):
        """
        Set the mapping for `key` to `value` and persist the updated dictionary to disk.
        
        This overwrites any existing entry for `key` and immediately saves the SCARPickles instance to its associated pickle file.
        
        Parameters:
            key: Hashable key used to store the value.
            value: Value to store (serialized via pickle on save).
        
        Returns:
            None
        """
        self[key] = value
        self.save()
        
    def append(self, key, value):
        """
        Append a value to an existing iterable stored under `key` and persist the change.
        
        If `key` exists and its current value is an iterable that supports `.append()` (e.g., list),
        the function appends `value` to that iterable. In all cases the method calls `save()` to
        persist the current state.
        
        Parameters:
            key: The dictionary key whose associated iterable should receive the new value.
            value: The item to append to the iterable stored at `key`.
        
        Returns:
            None
        """
        if key in self.keys() and isinstance(self[key], Iterable):
            self[key].append(value)
        self.save()
        
    def save(self):
        """
        Persist the dictionary to a pickle file at application_path/data/{pickle_name}.pkl.
        
        If the instance contains the keys 'application_path' and 'pickle_name', serializes the entire mapping (self) with pickle to a file named '{pickle_name}.pkl' inside the 'data' subdirectory of application_path. If either required key is missing, the method returns without performing any I/O.
        
        Side effects:
        - Creates/overwrites the target pickle file.
        - Uses binary write mode and pickle.dump for serialization.
        """
        if 'application_path' in self.keys() and 'pickle_name' in self.keys():
            with open(os.path.join(self['application_path'], "data", f"{self['pickle_name']}.pkl"), "wb") as f:
                pickle.dump(self, f)