# /opt/srt-streamer-enhanced/app/forms.py
# Contains Flask-WTF form definitions for the SRT Streamer application.
# Based on the user-provided working version, but with the enhanced NetworkTestForm added back.

from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    IntegerField,
    SelectField,
    RadioField, # Added for enhanced NetworkTestForm modes
    PasswordField, # Kept in case used elsewhere
    BooleanField, # Added for QoS
    FileField
)
from wtforms.validators import (
    DataRequired,
    Length,
    NumberRange, # Modified for Overhead
    Optional,
    ValidationError
)
from wtforms.widgets import html_params, Input
from markupsafe import Markup
from flask_wtf.file import FileAllowed

# --- Custom Widget for Percentage Input ---
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

# --- Main StreamForm (From User's Working Version) ---
class StreamForm(FlaskForm):
    """
    Form for configuring and starting SRT streams, primarily used for Listener mode
    on the main dashboard. Includes common parameters and listener-specific ones.
    """
    # Port selection (Listener Mode)
    port = SelectField(
        'Port',
        choices=[(str(port), str(port)) for port in range(10001, 10011)], # Ports 10001-10010
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
        default=300, # Default latency
        render_kw={
            'class': 'form-control',
            'min': '20',
            'max': '8000',
            'aria-describedby': 'latencyHelp'
        }
    )

    # Overhead bandwidth (updated range 1-99%)
    overhead_bandwidth = IntegerField(
        'Overhead Bandwidth',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=99, message="Overhead must be between 1% and 99%") # MODIFIED Range
        ],
        default=25, # Default overhead
        widget=PercentageInput(), # Use custom widget
        render_kw={
            'class': 'form-control',
            'min': '1',   # MODIFIED min
            'max': '99',  # MODIFIED max
            'step': '1',
            'aria-describedby': 'overheadHelp'
        },
        description="Extra bandwidth reserved for packet recovery (SRT Guide recommends 1-99%)"
    )

    # Mode selection
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

    # Target address
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
        default='none', # Default to no encryption
        render_kw={
            'class': 'form-select',
            'aria-describedby': 'encryptionHelp'
        }
    )

    # Passphrase field
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

    # QoS Field
    qos = BooleanField(
        'Enable QoS',
        default=False, # Default to disabled
        render_kw={
            'class': 'form-check-input'
        },
        description="Enable Quality of Service flag (qos=true) for SRT URI"
    )

    # DVB compliance toggle
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

    # Extended validation method
    def validate(self, extra_validators=None):
        """
        Extended validation with custom rules for encryption and caller mode requirements.
        """
        if not super().validate(extra_validators):
            return False
        if self.encryption.data != 'none' and not self.passphrase.data:
            self.passphrase.errors.append('Passphrase is required when encryption is enabled')
            return False
        # SRT passphrase length validation (strict 10-79)
        if self.encryption.data != 'none' and self.passphrase.data and (len(self.passphrase.data) < 10 or len(self.passphrase.data) > 79):
             self.passphrase.errors.append('Passphrase must be between 10 and 79 characters for SRT.')
             # return False # Uncomment if strictness required

        if self.mode.data == 'caller' and not self.target_address.data:
            self.target_address.errors.append('Target address is required in Caller mode')
            return False
        if self.target_address.data:
            if not self._validate_target_address(self.target_address.data):
                self.target_address.errors.append('Invalid target address format (IP or hostname)')
                return False
        return True

    def _validate_target_address(self, address):
        """ Basic validation for IP address or hostname format. """
        if not address or len(address) > 255: return False
        if any(c.isspace() for c in address): return False
        return True

# --- Dedicated CallerForm (From User's Working Version) ---
class CallerForm(FlaskForm):
    """
    Form specifically for configuring and starting SRT streams in Caller mode.
    """
    target_address = StringField(
        'Target Host/IP',
        validators=[DataRequired(), Length(max=255)],
        render_kw={'placeholder': 'e.g., 192.168.1.100 or ird.example.com', 'class': 'form-control'}
    )
    target_port = IntegerField(
        'Target Port',
        validators=[DataRequired(), NumberRange(min=1, max=65535)],
        default=10001, # Default target port
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
        default=300, # Default latency
        render_kw={'class': 'form-control', 'min': '20', 'max': '8000'}
    )
    overhead_bandwidth = IntegerField(
        'Overhead Bandwidth',
        validators=[DataRequired(), NumberRange(min=1, max=99)], # MODIFIED Range
        default=25, # Default overhead
        widget=PercentageInput(), # Use custom widget
        render_kw={
            'class': 'form-control',
            'min': '1',   # MODIFIED min
            'max': '99',  # MODIFIED max
            'step': '1'
        },
        description="Extra bandwidth for packet recovery (SRT Guide recommends 1-99%)"
    )
    encryption = SelectField(
        'Encryption',
        choices=[('none', 'None'), ('aes-128', 'AES-128'), ('aes-256', 'AES-256')],
        default='none', # Default to no encryption
        render_kw={'class': 'form-select'}
    )
    passphrase = StringField(
        'Passphrase',
        validators=[Optional(), Length(min=10, max=128)],
        render_kw={'placeholder': 'Required if encryption enabled', 'class': 'form-control'}
    )
    qos = BooleanField(
        'Enable QoS',
        default=False, # Default to disabled
        render_kw={
            'class': 'form-check-input'
        },
        description="Enable Quality of Service flag (qos=true) for SRT URI"
    )

    def validate(self, extra_validators=None):
        """
        Extended validation ensuring encryption passphrase and target address format are correct.
        """
        if not super().validate(extra_validators):
            return False
        if self.encryption.data != 'none' and not self.passphrase.data:
            self.passphrase.errors.append('Passphrase is required when encryption is enabled.')
            return False
        # SRT passphrase length validation (strict 10-79)
        if self.encryption.data != 'none' and self.passphrase.data and (len(self.passphrase.data) < 10 or len(self.passphrase.data) > 79):
             self.passphrase.errors.append('Passphrase must be between 10 and 79 characters for SRT.')
             # return False # Uncomment if strictness required

        if not self._validate_target_address(self.target_address.data):
            self.target_address.errors.append('Invalid target address format (IP or hostname).')
            return False
        return True

    def _validate_target_address(self, address):
        """ Basic validation for IP address or hostname format. """
        if not address or len(address) > 255: return False
        if any(c.isspace() for c in address): return False
        return True

# --- *** REPLACED NetworkTestForm with Enhanced Version *** ---
class NetworkTestForm(FlaskForm):
    """
    ENHANCED Form for network testing configuration, supporting different modes
    and protocol selection for manual mode.
    """
    mode = RadioField(
        'Test Mode',
        choices=[
            ('closest', 'Auto (Closest)'),
            ('regional', 'Auto (Regional)'),
            ('manual', 'Manual')
        ],
        default='closest',
        validators=[DataRequired()]
    )

    region = SelectField(
        'Select Region',
        choices=[('', '-- Select Region --')], # Populated dynamically in routes
        validators=[Optional()], # Required only if mode is regional
        render_kw={'class': 'form-select'}
    )

    manual_host = StringField(
        'Server IP / URL',
        validators=[Optional(), Length(min=3, max=255)], # Required only if mode is manual
        render_kw={'placeholder': 'e.g., iperf.example.com', 'class': 'form-control'}
    )

    manual_port = IntegerField(
        'Port',
        validators=[Optional(), NumberRange(min=1, max=65535)], # Optional, defaults likely used if empty
        render_kw={'placeholder': 'e.g., 5201', 'class': 'form-control'}
    )

    # Added: Protocol selection for Manual mode
    manual_protocol = SelectField(
        'Protocol (Manual Only)',
        choices=[
            ('udp', 'UDP'),
            ('tcp', 'TCP')
        ],
        default='udp', # Default to UDP for manual
        validators=[Optional()], # Only relevant if mode is manual
        render_kw={'class': 'form-select'}
    )

    duration = IntegerField(
        'Test Duration (sec)',
        default=5,
        validators=[DataRequired(), NumberRange(min=3, max=10)], # Short duration suitable for web UI
        render_kw={'class': 'form-control', 'min': '3', 'max': '10'}
    )

    bitrate = SelectField(
        'Test Bitrate (UDP)', # Label clarifies this is primarily for UDP tests
        choices=[('5M', '5 Mbps'), ('10M', '10 Mbps'), ('20M', '20 Mbps'), ('50M', '50 Mbps')],
        default='10M',
        validators=[DataRequired()],
        render_kw={'class': 'form-select'}
    )

    def validate(self, extra_validators=None):
        """ Validate based on selected mode """
        valid = super(NetworkTestForm, self).validate(extra_validators=extra_validators)
        if not valid:
            return False
        if self.mode.data == 'manual' and not self.manual_host.data:
            self.manual_host.errors.append('Manual host/IP is required when Mode is set to Manual.')
            return False
        if self.mode.data == 'regional' and not self.region.data:
            if len(self.region.choices) <= 1:
                 self.region.errors.append('Region choices could not be loaded. Cannot validate selection.')
            else:
                 self.region.errors.append('Region selection is required when Mode is set to Auto (Regional).')
            return False
        return True
# --- *** END ENHANCED NetworkTestForm *** ---


# --- MediaUploadForm (From User's Working Version) ---
class MediaUploadForm(FlaskForm):
    """
    Form for uploading media files (.ts format only).
    """
    media_file = FileField(
        'Media File',
        validators=[
            DataRequired(),
            FileAllowed(['ts'], 'Only TS files (.ts) are supported')
        ],
        render_kw={
            'class': 'form-control',
            'accept': '.ts' # Hint for browser file selection
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

# --- SettingsForm (From User's Working Version) ---
class SettingsForm(FlaskForm):
    """
    Form for potential future system settings (e.g., max streams, logging).
    (Currently unused in routes, but defined here for structure)
    """
    max_streams = IntegerField(
        'Maximum Concurrent Streams',
        validators=[
            DataRequired(),
            NumberRange(min=1, max=10) # Example range
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
