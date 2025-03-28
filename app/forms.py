# Full content for app/forms.py

from flask_wtf import FlaskForm
from wtforms import (
    StringField, 
    IntegerField, 
    SelectField, 
    PasswordField, # Kept in case used elsewhere, though StreamForm uses StringField now
    BooleanField, 
    FileField
)
from wtforms.validators import (
    DataRequired, 
    Length, 
    NumberRange, 
    Optional, 
    ValidationError
)
from wtforms.widgets import html_params, Input
from markupsafe import Markup
from flask_wtf.file import FileAllowed

# --- Custom Widget (already present) ---
class PercentageInput(Input):
    """
    Custom input widget that adds a percentage sign after the input field
    """
    def __call__(self, field, **kwargs):
        kwargs.setdefault('id', field.id)
        kwargs.setdefault('type', 'number')
        if 'required' not in kwargs and 'required' in getattr(field, 'flags', []):
            kwargs['required'] = True
        return Markup('<div class="input-group">'
                     '<input %s>'
                     '<span class="input-group-text">%%</span>'
                     '</div>' % html_params(name=field.name, 
                                          value=field._value(),
                                          **kwargs))

# --- Existing StreamForm (Listener/Caller combined, modified validation) ---
# Note: StreamForm already handles listener/caller selection. 
# We can potentially keep using this form and adapt the route logic,
# OR use the new CallerForm specifically for the /caller route. 
# Let's keep StreamForm as it was for the index page, and add CallerForm for the new page.
class StreamForm(FlaskForm):
    # Port selection as dropdown (10001-10010) - For Listener Mode
    port = SelectField(
        'Port',
        choices=[(str(port), str(port)) for port in range(10001, 10011)],  # 10001-10010
        default='10001',
        validators=[DataRequired()],
        render_kw={
            'class': 'form-select',
            'aria-describedby': 'portHelp'
        }
    )
    
    # File path field
    file_path = StringField(
        'File Path',
        validators=[DataRequired()],
        render_kw={
            'placeholder': 'Select media file',
            'class': 'form-control',
            'aria-describedby': 'fileHelp'
        }
    )
    
    # Latency configuration
    latency = IntegerField(
        'Latency (ms)',
        validators=[
            DataRequired(),
            NumberRange(min=20, max=8000, message="Latency must be between 20 and 8000 ms")
        ],
        default=300,
        render_kw={
            'class': 'form-control',
            'min': '20',
            'max': '8000',
            'aria-describedby': 'latencyHelp'
        }
    )
    
    # Overhead bandwidth (updated range 10-66%)
    overhead_bandwidth = IntegerField(
        'Overhead Bandwidth',
        validators=[
            DataRequired(),
            NumberRange(min=10, max=66, message="Overhead must be between 10% and 66%")
        ],
        default=25,
        widget=PercentageInput(),
        render_kw={
            'class': 'form-control',
            'min': '10',
            'max': '66',
            'step': '1',
            'aria-describedby': 'overheadHelp'
        },
        description="Extra bandwidth reserved for packet recovery (25-33% recommended)"
    )
    
    # Mode selection (Listener/Caller)
    mode = SelectField(
        'Mode',
        choices=[
            ('listener', 'Listener (Server)'),
            ('caller', 'Caller (Client)')
        ],
        default='listener',
        render_kw={
            'class': 'form-select',
            'aria-describedby': 'modeHelp'
        }
    )
    
    # Target address (only shown in caller mode)
    target_address = StringField(
        'Target Address',
        validators=[
            Optional(), 
            Length(max=255)
        ],
        render_kw={
            'placeholder': 'Required for Caller mode',
            'class': 'form-control',
            'aria-describedby': 'targetHelp'
        }
    )
    
    # Encryption selection
    encryption = SelectField(
        'Encryption',
        choices=[
            ('none', 'None'),
            ('aes-128', 'AES-128'),
            ('aes-256', 'AES-256')
        ],
        default='none',
        render_kw={
            'class': 'form-select',
            'aria-describedby': 'encryptionHelp'
        }
    )
    
    # Passphrase field - StringField to allow visibility
    passphrase = StringField(
        'Passphrase',
        validators=[
            Optional(),
            Length(min=10, max=128, message="Passphrase must be 10-128 characters")
        ],
        render_kw={
            'placeholder': 'Required if encryption enabled',
            'class': 'form-control',
            'aria-describedby': 'passphraseHelp'
        }
    )
    
    # DVB compliance toggle (kept as disabled True)
    dvb_compliant = BooleanField(
        'DVB Compliant',
        default=True,
        render_kw={
            'class': 'form-check-input',
            'disabled': True,
            'aria-describedby': 'dvbHelp'
        },
        description="DVB compliance is mandatory for all streams"
    )

    def validate(self, extra_validators=None):
        """
        Extended validation with custom rules
        """
        if not super().validate(extra_validators):
            return False
        
        # Validate encryption requirements
        if self.encryption.data != 'none' and not self.passphrase.data:
            self.passphrase.errors.append('Passphrase is required when encryption is enabled')
            return False
            
        # Validate caller mode requirements
        if self.mode.data == 'caller' and not self.target_address.data:
            self.target_address.errors.append('Target address is required in Caller mode')
            return False
            
        # Validate target address format if provided
        if self.target_address.data:
            if not self._validate_target_address(self.target_address.data):
                self.target_address.errors.append('Invalid target address format (IP or hostname)')
                return False
            
        # Warnings for overhead bandwidth are fine, no need to return False
        if self.overhead_bandwidth.data: # Check if data exists
            if self.overhead_bandwidth.data < 15:
                 # Consider adding a non-blocking warning if needed, but don't fail validation
                 pass 
            elif self.overhead_bandwidth.data > 50:
                 # Consider adding a non-blocking warning
                 pass
            
        return True
    
    def _validate_target_address(self, address):
        """ Basic validation for IP or hostname """
        if not address or len(address) > 255: return False
        # Very basic checks, could be improved with regex
        if any(c in address for c in ' \t\n\r'): return False 
        return True

# --- NEW CallerForm ---
class CallerForm(FlaskForm):
    target_address = StringField(
        'Target Host/IP', 
        validators=[DataRequired(), Length(max=255)],
        render_kw={'placeholder': 'e.g., 192.168.1.100 or ird.example.com', 'class': 'form-control'}
    )
    target_port = IntegerField(
        'Target Port', 
        validators=[DataRequired(), NumberRange(min=1, max=65535)],
        default=10001, 
        render_kw={'class': 'form-control', 'min': '1', 'max': '65535'}
    )
    file_path = StringField(
        'File Path',
        validators=[DataRequired()],
        render_kw={
            'placeholder': 'Select media file',
            'class': 'form-control',
            'aria-describedby': 'fileHelpCaller' 
        }
    )
    latency = IntegerField(
        'Latency (ms)',
        validators=[DataRequired(), NumberRange(min=20, max=8000)],
        default=300,
        render_kw={'class': 'form-control', 'min': '20', 'max': '8000'}
    )
    overhead_bandwidth = IntegerField(
        'Overhead Bandwidth',
        validators=[DataRequired(), NumberRange(min=10, max=66)],
        default=25,
        widget=PercentageInput(), 
        render_kw={'class': 'form-control', 'min': '10', 'max': '66', 'step': '1'},
        description="Extra bandwidth for packet recovery (25-33% recommended)"
    )
    encryption = SelectField(
        'Encryption',
        choices=[('none', 'None'), ('aes-128', 'AES-128'), ('aes-256', 'AES-256')],
        default='none',
        render_kw={'class': 'form-select'}
    )
    passphrase = StringField(
        'Passphrase',
        validators=[Optional(), Length(min=10, max=128)],
        render_kw={'placeholder': 'Required if encryption enabled', 'class': 'form-control'}
    )
    
    # DVB compliance hidden or not shown, assumed True based on StreamForm
    # dvb_compliant = BooleanField('DVB Compliant', default=True) 

    def validate(self, extra_validators=None):
        if not super().validate(extra_validators):
            return False
        if self.encryption.data != 'none' and not self.passphrase.data:
            self.passphrase.errors.append('Passphrase is required for encryption.')
            return False
        # Add more validation if needed (e.g., target address format)
        if not self._validate_target_address(self.target_address.data):
             self.target_address.errors.append('Invalid target address format (IP or hostname)')
             return False
        return True

    def _validate_target_address(self, address):
        """ Basic validation for IP or hostname """
        if not address or len(address) > 255: return False
        # Very basic checks, could be improved with regex
        if any(c in address for c in ' \t\n\r'): return False 
        return True

# --- Other Existing Forms (ensure they are still here) ---
class NetworkTestForm(FlaskForm):
    """
    Form for network testing configuration
    """
    target = StringField(
        'Target Server',
        validators=[Optional()],
        render_kw={
            'placeholder': 'Leave blank for automatic selection',
            'class': 'form-control'
        }
    )
    
    duration = IntegerField(
        'Test Duration (seconds)',
        validators=[
            DataRequired(),
            NumberRange(min=3, max=10)
        ],
        default=5,
        render_kw={
            'class': 'form-control',
            'min': '3',
            'max': '10'
        }
    )
    
    bitrate = SelectField(
        'Test Bitrate',
        choices=[
            ('5M', '5 Mbps'),
            ('10M', '10 Mbps'),
            ('20M', '20 Mbps'),
            ('50M', '50 Mbps')
        ],
        default='10M',
        render_kw={
            'class': 'form-select'
        }
    )

class MediaUploadForm(FlaskForm):
    """
    Form for media file uploads
    """
    media_file = FileField(
        'Media File',
        validators=[
            DataRequired(),
            FileAllowed(['ts'], 'Only TS files are supported')
        ],
        render_kw={
            'class': 'form-control',
            'accept': '.ts'
        }
    )
    
    description = StringField(
        'Description',
        validators=[Optional(), Length(max=255)],
        render_kw={
            'placeholder': 'Optional file description',
            'class': 'form-control'
        }
    )

class SettingsForm(FlaskForm):
    """
    Form for system settings
    """
    max_streams = IntegerField(
        'Maximum Concurrent Streams',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=10)
        ],
        default=5,
        render_kw={
            'class': 'form-control',
            'min': '1',
            'max': '10'
        }
    )
    
    auto_restart = BooleanField(
        'Auto-restart Failed Streams',
        default=True,
        render_kw={
            'class': 'form-check-input'
        }
    )
    
    log_level = SelectField(
        'Logging Level',
        choices=[
            ('DEBUG', 'Debug'),
            ('INFO', 'Info'),
            ('WARNING', 'Warning'),
            ('ERROR', 'Error')
        ],
        default='INFO',
        render_kw={
            'class': 'form-select'
        }
    )
