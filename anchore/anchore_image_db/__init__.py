import importlib
import anchore.anchore_image_db.anchore_image_db_fs as t

def load(driver=None, config={}):
    """
    Load the Anchore DB driver based on the requested driver name.
    Uses importlib to avoid circular import issues.
    """
    dbobj = None

    # Map of driver names to their module paths
    driver_map = {
        "AnchoreImageDB_FS": "anchore.anchore_image_db.anchore_image_db_fs",
        "AnchoreModulesImageDB_FS": "anchore_modules.anchore_image_db",
    }

    if driver not in driver_map:
        raise Exception(f"DB driver not found: {driver}")

    module_path = driver_map[driver]
    module = importlib.import_module(module_path)
    print(module)

      # Try to find a module-level 'load' function first
    if hasattr(module, 'load') and callable(module.load):
        print('WTF')
        # The 'load' function exists in the module, call that directly
        dbobj = module.load(config=config)
    
    # Fallback for the original implementation style (class method 'load')
    elif hasattr(module, driver) and hasattr(getattr(module, driver), 'load'):
        driver_class = getattr(module, driver)
        dbobj = driver_class.load(config=config)
        
    else:
        # If neither pattern is found, raise an error
        raise AttributeError(f"Driver module {module_path} does not have a valid 'load' function or class method 'load'.")
    print(dbobj)
    return dbobj
