"""
Mathematical Periodicity and Inter-Arrival Time (IAT) Analysis for Trinetra.
Specifically engineered for T-b (Botnet C2 Beaconing) detection.
Computes:
1. IAT Statistics (Mean, Std, Coefficient of Variation CV)
2. Normalized Autocorrelation Function (ACF)
3. Fast Fourier Transform (FFT) Spectral Peak Power & Dominant Frequency
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple
import numpy as np
from scipy import signal


@dataclass
class PeriodicityProfile:
    contact_count: int
    mean_iat: float
    std_iat: float
    cv_iat: float  # Coefficient of variation = std / mean
    is_periodic: bool
    is_jittered_periodic: bool
    dominant_frequency: float
    dominant_period: float
    spectral_power: float
    autocorr_peak: float


def analyze_periodicity(timestamps: List[float], min_samples: int = 6) -> Optional[PeriodicityProfile]:
    """
    Analyzes a sequence of flow connection timestamps (Unix epoch seconds)
    to detect periodic C2 beaconing.
    """
    if len(timestamps) < min_samples:
        return None

    # Sort timestamps in ascending order
    ts = np.sort(np.asarray(timestamps, dtype=np.float64))
    diffs = np.diff(ts)

    # Filter out near-zero simultaneous connection artifacts (<0.05s)
    diffs = diffs[diffs > 0.05]
    if len(diffs) < (min_samples - 1):
        return None

    mean_iat = float(np.mean(diffs))
    std_iat = float(np.std(diffs))
    cv_iat = float(std_iat / mean_iat) if mean_iat > 0 else 1.0

    # 1. Autocorrelation analysis
    # Normalize diffs
    centered = diffs - mean_iat
    var = np.var(diffs)
    if var > 1e-6 and len(diffs) >= 4:
        autocorr = np.correlate(centered, centered, mode='full')
        autocorr = autocorr[len(autocorr)//2:] / (var * len(diffs))
        # Ignore lag 0, find peak in lag >= 1
        autocorr_peak = float(np.max(autocorr[1:min(len(autocorr), 10)])) if len(autocorr) > 1 else 0.0
    else:
        autocorr_peak = 1.0 if var <= 1e-6 else 0.0

    # 2. FFT Spectral Analysis
    # Discretize timestamps into 1-second activity bins
    start_t = ts[0]
    end_t = ts[-1]
    duration = end_t - start_t
    if duration > 10.0 and len(ts) >= 6:
        num_bins = int(min(duration + 1, 1024))
        hist, _ = np.histogram(ts, bins=num_bins, range=(start_t, end_t))
        hist = hist - np.mean(hist)
        
        # Compute FFT magnitude
        fft_vals = np.abs(np.fft.rfft(hist))
        freqs = np.fft.rfftfreq(num_bins, d=(duration / num_bins))
        
        # Skip zero/DC component
        if len(fft_vals) > 1:
            fft_vals[0] = 0
            peak_idx = int(np.argmax(fft_vals))
            dominant_freq = float(freqs[peak_idx])
            dominant_period = float(1.0 / dominant_freq) if dominant_freq > 0 else 0.0
            
            # Spectral power ratio (peak energy / total energy)
            total_energy = float(np.sum(fft_vals))
            spectral_power = float(fft_vals[peak_idx] / total_energy) if total_energy > 0 else 0.0
        else:
            dominant_freq = 0.0
            dominant_period = mean_iat
            spectral_power = 0.0
    else:
        dominant_freq = float(1.0 / mean_iat) if mean_iat > 0 else 0.0
        dominant_period = mean_iat
        spectral_power = 0.9 if cv_iat < 0.1 else 0.5

    # Classification rules:
    # Rigid beacon: CV < 0.20
    # Jittered beacon (e.g. Cobalt Strike 20% jitter): 0.15 <= CV <= 0.38 with high autocorr or spectral power
    is_rigid = (cv_iat < 0.22)
    is_jittered = (cv_iat < 0.38 and (autocorr_peak > 0.50 or spectral_power > 0.30))

    return PeriodicityProfile(
        contact_count=len(ts),
        mean_iat=mean_iat,
        std_iat=std_iat,
        cv_iat=cv_iat,
        is_periodic=is_rigid,
        is_jittered_periodic=is_jittered,
        dominant_frequency=dominant_freq,
        dominant_period=dominant_period,
        spectral_power=spectral_power,
        autocorr_peak=autocorr_peak
    )
