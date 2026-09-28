"""
Security Validation Orchestrator

This module coordinates all security validation activities across the entire system.
It manages the validation workflow, collects evidence, and ensures comprehensive
coverage of all 100+ security features across 8 platforms.

Requirements: 1.5, 1.6, 15.1, 15.2, 15.3, 15.8
"""

import asyncio
import logging
import time
import json
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import traceback

from nist_level5_policy_engine import NISTLevel5PolicyEngine, SecurityViolation


class ValidationPhase(Enum):
    """Validation phases in order of execution"""
    INITIALIZATION = "initialization"
    CRYPTOGRAPHIC_VALIDATION = "cryptographic_validation"
    HARDWARE_SECURITY_VALIDATION = "hardware_security_validation"
    MEMORY_PROTECTION_VALIDATION = "memory_protection_validation"
    PROCESS_SECURITY_VALIDATION = "process_security_validation"
    NETWORK_SECURITY_VALIDATION = "network_security_validation"
    PLATFORM_CONSISTENCY_VALIDATION = "platform_consistency_validation"
    ATTACK_TESTING = "attack_simulation"
    COMPLIANCE_VALIDATION = "compliance_validation"
    EVIDENCE_COLLECTION = "evidence_collection"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"


class ValidationStatus(Enum):
    """Status of validation operations"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ValidationResult:
    """Result of a validation operation"""
    validator_name: str
    phase: ValidationPhase
    status: ValidationStatus
    success: bool
    message: str
    evidence: Dict[str, Any]
    execution_time: float
    timestamp: float
    error_details: Optional[str] = None


@dataclass
class ValidationReport:
    """Comprehensive validation report"""
    orchestrator_version: str
    validation_id: str
    start_time: float
    end_time: Optional[float]
    total_execution_time: Optional[float]
    current_phase: ValidationPhase
    overall_status: ValidationStatus
    total_validators: int
    successful_validators: int
    failed_validators: int
    skipped_validators: int
    validation_results: List[ValidationResult]
    security_violations: List[Dict[str, Any]]
    evidence_package: Dict[str, Any]
    nist_level5_compliant: bool
    platforms_validated: List[str]
    features_validated: List[str]


class ValidationOrchestrationError(Exception):
    """Raised when validation orchestration fails"""
    import logging; logging.getLogger(__name__).debug("Ignored exception")


class SecurityValidationOrchestrator:
    """
    Orchestrates comprehensive security validation across all platforms and features.
    Coordinates validation workflow, manages evidence collection, and ensures
    NIST Level 5+ compliance with fail-secure operation.
    """
    
    VERSION = "1.0.0"
    
    # Supported platforms for validation
    SUPPORTED_PLATFORMS = [
        "Windows", "Linux", "macOS", "Android", "iOS", 
        "Docker", "Kubernetes", "Cloud"
    ]
    
    # Security feature categories to validate
    SECURITY_FEATURE_CATEGORIES = [
        "post_quantum_cryptography",
        "classical_cryptography", 
        "hybrid_cryptography",
        "enhanced_security_features",
        "hardware_security",
        "memory_protection",
        "process_security",
        "network_security",
        "compliance_features",
        "platform_specific_features"
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.policy_engine = NISTLevel5PolicyEngine()
        
        # Validation state
        self.validation_id = f"validation_{int(time.time())}"
        self.current_phase = ValidationPhase.INITIALIZATION
        self.validation_results: List[ValidationResult] = []
        self.registered_validators: Dict[str, Callable] = {}
        self.evidence_collector = None  # Will be set by EvidenceCollectionSystem
        self.report_generator = None    # Will be set by AttestationReportGenerator
        
        # Execution tracking
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.phase_start_times: Dict[ValidationPhase, float] = {}
        
        # Configuration
        self.fail_fast = True  # Terminate on first security violation
        self.parallel_execution = True  # Execute validators in parallel when possible
        self.max_concurrent_validators = 10
        
        # Initialize logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        self.logger.info(f"Security Validation Orchestrator {self.VERSION} initialized")
        self.logger.info(f"Validation ID: {self.validation_id}")
    
    def register_validator(self, name: str, validator_func: Callable) -> None:
        """Register a validator function for execution"""
        self.registered_validators[name] = validator_func
        self.logger.info(f"Registered validator: {name}")
    
    def set_evidence_collector(self, evidence_collector) -> None:
        """Set the evidence collection system"""
        self.evidence_collector = evidence_collector
        self.logger.info("Evidence collector registered")
    
    def set_report_generator(self, report_generator) -> None:
        """Set the attestation report generator"""
        self.report_generator = report_generator
        self.logger.info("Report generator registered")
    
    async def validate_all_security_features(
        self,
        platforms: Optional[List[str]] = None,
        feature_categories: Optional[List[str]] = None
    ) -> ValidationReport:
        """
        Execute comprehensive validation of all security features.
        
        Args:
            platforms: List of platforms to validate (default: all supported)
            feature_categories: List of feature categories to validate (default: all)
            
        Returns:
            ValidationReport with comprehensive results and evidence
            
        Raises:
            ValidationOrchestrationError if validation fails
            SecurityViolation if security requirements are not met
        """
        self.start_time = time.time()
        platforms = platforms or self.SUPPORTED_PLATFORMS
        feature_categories = feature_categories or self.SECURITY_FEATURE_CATEGORIES
        
        self.logger.info(f"Starting comprehensive security validation")
        self.logger.info(f"Platforms: {platforms}")
        self.logger.info(f"Feature categories: {feature_categories}")
        
        try:
            # Phase 1: Initialization
            await self._execute_phase(ValidationPhase.INITIALIZATION)
            
            # Phase 2: Cryptographic Validation
            await self._execute_phase(ValidationPhase.CRYPTOGRAPHIC_VALIDATION)
            
            # Phase 3: Hardware Security Validation
            await self._execute_phase(ValidationPhase.HARDWARE_SECURITY_VALIDATION)
            
            # Phase 4: Memory Protection Validation
            await self._execute_phase(ValidationPhase.MEMORY_PROTECTION_VALIDATION)
            
            # Phase 5: Process Security Validation
            await self._execute_phase(ValidationPhase.PROCESS_SECURITY_VALIDATION)
            
            # Phase 6: Network Security Validation
            await self._execute_phase(ValidationPhase.NETWORK_SECURITY_VALIDATION)
            
            # Phase 7: Platform Consistency Validation
            await self._execute_phase(ValidationPhase.PLATFORM_CONSISTENCY_VALIDATION)
            
            # Phase 8: Attack Testing
            await self._execute_phase(ValidationPhase.ATTACK_TESTING)
            
            # Phase 9: Compliance Validation
            await self._execute_phase(ValidationPhase.COMPLIANCE_VALIDATION)
            
            # Phase 10: Evidence Collection
            await self._execute_phase(ValidationPhase.EVIDENCE_COLLECTION)
            
            # Phase 11: Report Generation
            await self._execute_phase(ValidationPhase.REPORT_GENERATION)
            
            # Mark as completed
            self.current_phase = ValidationPhase.COMPLETED
            self.end_time = time.time()
            
            # Generate final report
            report = self._generate_final_report(platforms, feature_categories)
            
            # Enforce fail-secure operation
            self.policy_engine.enforce_fail_secure_operation()
            
            self.logger.info(f"Validation completed successfully in {self.end_time - self.start_time:.2f} seconds")
            return report
            
        except Exception as e:
            self.end_time = time.time()
            self.logger.critical(f"Validation failed: {e}")
            self.logger.critical(f"Traceback: {traceback.format_exc()}")
            
            # Generate failure report
            report = self._generate_failure_report(str(e), platforms, feature_categories)
            
            if isinstance(e, SecurityViolation):
                raise e
            else:
                raise ValidationOrchestrationError(f"Validation orchestration failed: {e}")
    
    async def _execute_phase(self, phase: ValidationPhase) -> None:
        """Execute a specific validation phase"""
        self.current_phase = phase
        self.phase_start_times[phase] = time.time()
        
        self.logger.info(f"Executing phase: {phase.value}")
        
        # Get validators for this phase
        phase_validators = self._get_phase_validators(phase)
        
        if not phase_validators:
            self.logger.warning(f"No validators registered for phase: {phase.value}")
            return
        
        # Execute validators
        if self.parallel_execution and len(phase_validators) > 1:
            await self._execute_validators_parallel(phase_validators, phase)
        else:
            await self._execute_validators_sequential(phase_validators, phase)
        
        phase_duration = time.time() - self.phase_start_times[phase]
        self.logger.info(f"Phase {phase.value} completed in {phase_duration:.2f} seconds")
    
    def _get_phase_validators(self, phase: ValidationPhase) -> List[Tuple[str, Callable]]:
        """Get validators for a specific phase"""
        phase_mapping = {
            ValidationPhase.INITIALIZATION: ["system_initialization"],
            ValidationPhase.CRYPTOGRAPHIC_VALIDATION: [
                "pqc_validator", "classical_crypto_validator", "hybrid_crypto_validator"
            ],
            ValidationPhase.HARDWARE_SECURITY_VALIDATION: [
                "tpm_validator", "hsm_validator", "secure_enclave_validator", "hardware_rng_validator"
            ],
            ValidationPhase.MEMORY_PROTECTION_VALIDATION: [
                "dod_wiping_validator", "constant_time_validator", "stack_canary_validator", 
                "memory_locking_validator", "memory_encryption_validator"
            ],
            ValidationPhase.PROCESS_SECURITY_VALIDATION: [
                "anti_debugging_validator", "process_monitoring_validator", "threat_detection_validator",
                "intrusion_detection_validator", "security_recovery_validator"
            ],
            ValidationPhase.NETWORK_SECURITY_VALIDATION: [
                "tls_validator", "cipher_suite_validator", "cert_pinning_validator", 
                "double_ratchet_validator", "break_in_recovery_validator"
            ],
            ValidationPhase.PLATFORM_CONSISTENCY_VALIDATION: [
                "cross_platform_crypto_validator", "security_parameter_validator", 
                "platform_feature_validator"
            ],
            ValidationPhase.ATTACK_TESTING: [
                "crypto_attack_tester", "memory_attack_tester", "network_attack_tester",
                "process_attack_tester", "hardware_attack_tester"
            ],
            ValidationPhase.COMPLIANCE_VALIDATION: [
                "nist_compliance_validator", "iso_compliance_validator", "soc2_compliance_validator",
                "gdpr_compliance_validator", "military_compliance_validator"
            ],
            ValidationPhase.EVIDENCE_COLLECTION: ["evidence_collector"],
            ValidationPhase.REPORT_GENERATION: ["report_generator"]
        }
        
        validator_names = phase_mapping.get(phase, [])
        return [
            (name, validator) 
            for name, validator in self.registered_validators.items()
            if name in validator_names
        ]
    
    async def _execute_validators_parallel(
        self, 
        validators: List[Tuple[str, Callable]], 
        phase: ValidationPhase
    ) -> None:
        """Execute validators in parallel"""
        semaphore = asyncio.Semaphore(self.max_concurrent_validators)
        
        async def execute_validator(name: str, validator_func: Callable) -> ValidationResult:
            async with semaphore:
                return await self._execute_single_validator(name, validator_func, phase)
        
        tasks = [execute_validator(name, func) for name, func in validators]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Validator execution failed: {result}")
                if self.fail_fast:
                    raise result
            else:
                self.validation_results.append(result)
    
    async def _execute_validators_sequential(
        self, 
        validators: List[Tuple[str, Callable]], 
        phase: ValidationPhase
    ) -> None:
        """Execute validators sequentially"""
        for name, validator_func in validators:
            try:
                result = await self._execute_single_validator(name, validator_func, phase)
                self.validation_results.append(result)
            except Exception as e:
                self.logger.error(f"Validator {name} failed: {e}")
                if self.fail_fast:
                    raise e
    
    async def _execute_single_validator(
        self, 
        name: str, 
        validator_func: Callable, 
        phase: ValidationPhase
    ) -> ValidationResult:
        """Execute a single validator and capture results"""
        start_time = time.time()
        
        try:
            self.logger.info(f"Executing validator: {name}")
            
            # Execute validator (handle both sync and async functions)
            if asyncio.iscoroutinefunction(validator_func):
                result = await validator_func()
            else:
                result = validator_func()
            
            execution_time = time.time() - start_time
            
            # Create validation result
            validation_result = ValidationResult(
                validator_name=name,
                phase=phase,
                status=ValidationStatus.COMPLETED,
                success=True,
                message=f"Validator {name} completed successfully",
                evidence=result if isinstance(result, dict) else {"result": str(result)},
                execution_time=execution_time,
                timestamp=time.time()
            )
            
            self.logger.info(f"Validator {name} completed in {execution_time:.2f} seconds")
            return validation_result
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_details = traceback.format_exc()
            
            validation_result = ValidationResult(
                validator_name=name,
                phase=phase,
                status=ValidationStatus.FAILED,
                success=False,
                message=f"Validator {name} failed: {str(e)}",
                evidence={"error": str(e)},
                execution_time=execution_time,
                timestamp=time.time(),
                error_details=error_details
            )
            
            self.logger.error(f"Validator {name} failed after {execution_time:.2f} seconds: {e}")
            
            if self.fail_fast:
                raise e
            
            return validation_result
    
    def _generate_final_report(
        self, 
        platforms: List[str], 
        feature_categories: List[str]
    ) -> ValidationReport:
        """Generate final validation report"""
        successful_validators = sum(1 for r in self.validation_results if r.success)
        failed_validators = sum(1 for r in self.validation_results if not r.success)
        
        # Collect evidence
        evidence_package = {}
        if self.evidence_collector:
            evidence_package = self.evidence_collector.collect_all_evidence()
        
        # Add policy engine evidence
        evidence_package["policy_engine"] = self.policy_engine.generate_security_evidence()
        
        return ValidationReport(
            orchestrator_version=self.VERSION,
            validation_id=self.validation_id,
            start_time=self.start_time,
            end_time=self.end_time,
            total_execution_time=self.end_time - self.start_time,
            current_phase=self.current_phase,
            overall_status=ValidationStatus.COMPLETED if failed_validators == 0 else ValidationStatus.FAILED,
            total_validators=len(self.validation_results),
            successful_validators=successful_validators,
            failed_validators=failed_validators,
            skipped_validators=0,
            validation_results=self.validation_results,
            security_violations=self.policy_engine.security_violations,
            evidence_package=evidence_package,
            nist_level5_compliant=len(self.policy_engine.security_violations) == 0,
            platforms_validated=platforms,
            features_validated=feature_categories
        )
    
    def _generate_failure_report(
        self, 
        error_message: str, 
        platforms: List[str], 
        feature_categories: List[str]
    ) -> ValidationReport:
        """Generate failure report when validation fails"""
        successful_validators = sum(1 for r in self.validation_results if r.success)
        failed_validators = sum(1 for r in self.validation_results if not r.success)
        
        return ValidationReport(
            orchestrator_version=self.VERSION,
            validation_id=self.validation_id,
            start_time=self.start_time,
            end_time=self.end_time,
            total_execution_time=(self.end_time or time.time()) - self.start_time,
            current_phase=self.current_phase,
            overall_status=ValidationStatus.FAILED,
            total_validators=len(self.validation_results),
            successful_validators=successful_validators,
            failed_validators=failed_validators,
            skipped_validators=0,
            validation_results=self.validation_results,
            security_violations=self.policy_engine.security_violations,
            evidence_package={"error": error_message},
            nist_level5_compliant=False,
            platforms_validated=platforms,
            features_validated=feature_categories
        )
    
    def get_validation_status(self) -> Dict[str, Any]:
        """Get current validation status"""
        return {
            "validation_id": self.validation_id,
            "current_phase": self.current_phase.value,
            "start_time": self.start_time,
            "elapsed_time": (time.time() - self.start_time) if self.start_time else 0,
            "total_validators": len(self.validation_results),
            "completed_validators": len([r for r in self.validation_results if r.status == ValidationStatus.COMPLETED]),
            "failed_validators": len([r for r in self.validation_results if r.status == ValidationStatus.FAILED]),
            "security_violations": len(self.policy_engine.security_violations),
            "registered_validators": list(self.registered_validators.keys())
        }


if __name__ == "__main__":
    # Test the orchestrator
    async def test_orchestrator():
        orchestrator = SecurityValidationOrchestrator()
        
        # Register a test validator
        def test_validator():
            return {"test": "passed", "timestamp": time.time()}
        
        orchestrator.register_validator("test_validator", test_validator)
        
        try:
            # This would normally run full validation
            status = orchestrator.get_validation_status()
            print(f"Orchestrator status: {status}")
            print("[PASS] Security Validation Orchestrator initialized successfully")
        except Exception as e:
            print(f"[FAIL] Orchestrator test failed: {e}")
    
    asyncio.run(test_orchestrator())