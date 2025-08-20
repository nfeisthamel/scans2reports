from enum import Enum

class TestResultOptions(Enum):
    add     = 'add'
    convert = 'convert'
    close   = 'close'
    
    def __str__(self):
        """
        Return the underlying string value of the enum member.
        
        This returns the member's stored value (typically a string) so that str(member)
        produces the member's underlying value rather than the Enum representation.
        
        Returns:
            str: The enum member's underlying value.
        """
        return self.value
        
        
class MitigationStatementOptions(Enum):
    blank = 'blank'
    poam  = 'poam'
    ckl   = 'ckl'
    both  = 'both'
    
    def __str__(self):
        """
        Return the underlying string value of the enum member.
        
        This returns the member's stored value (typically a string) so that str(member)
        produces the member's underlying value rather than the Enum representation.
        
        Returns:
            str: The enum member's underlying value.
        """
        return self.value