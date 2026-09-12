package com.AcquantHR.AuditManagementSystem.ServiceImpl;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.AcquantHR.AuditManagementSystem.Entity.Audit;
import com.AcquantHR.AuditManagementSystem.Entity.Finding;
import com.AcquantHR.AuditManagementSystem.Entity.User;
import com.AcquantHR.AuditManagementSystem.Exception.ResourceNotFoundException;
import com.AcquantHR.AuditManagementSystem.Exception.UnauthorizedActionException;
import com.AcquantHR.AuditManagementSystem.Repo.AuditRepository;
import com.AcquantHR.AuditManagementSystem.Repo.FindingRepository;
import com.AcquantHR.AuditManagementSystem.Repo.UserRepository;
import com.AcquantHR.AuditManagementSystem.Service.FindingService;

@Service
public class FindingServiceImpl implements FindingService {

    private final FindingRepository findingRepository;
    private final UserRepository userRepository;
    private final AuditRepository auditRepository;

    public FindingServiceImpl(
            FindingRepository findingRepository,
            UserRepository userRepository,
            AuditRepository auditRepository) {

        this.findingRepository = findingRepository;
        this.userRepository = userRepository;
        this.auditRepository = auditRepository;
    }

    // =========================================================
    // GET LOGGED-IN USER
    // =========================================================

    private User getLoggedInUser() {

        Authentication authentication =
                SecurityContextHolder
                        .getContext()
                        .getAuthentication();

        String email = authentication.getName();

        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "User not found"));
    }

    // =========================================================
    // CREATE FINDING
    // =========================================================

    @Override
    public Finding createFinding(Finding finding) {

        User loggedInUser = getLoggedInUser();

        String role = loggedInUser.getRole() != null
                ? loggedInUser.getRole().getName()
                : null;

        // -----------------------------------------------------
        // Only ADMIN or AUDITOR can create finding
        // -----------------------------------------------------

        if (role == null ||
                (!"ADMIN".equalsIgnoreCase(role)
                        && !"AUDITOR".equalsIgnoreCase(role))) {

            throw new UnauthorizedActionException(
                    "Only ADMIN or AUDITOR can create finding");
        }

        // -----------------------------------------------------
        // Audit is required
        // -----------------------------------------------------

        if (finding.getAudit() == null ||
                finding.getAudit().getId() == null) {

            throw new ResourceNotFoundException(
                    "Audit ID is required");
        }

        Long auditId = finding.getAudit().getId();

        // -----------------------------------------------------
        // Find audit from database
        // -----------------------------------------------------

        Audit audit = auditRepository.findById(auditId)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Audit not found with id: " + auditId));

        // -----------------------------------------------------
        // AUDITOR can create finding only for assigned audit
        // -----------------------------------------------------

        if ("AUDITOR".equalsIgnoreCase(role)) {

            if (audit.getAuditor() == null ||
                    !audit.getAuditor()
                            .getId()
                            .equals(loggedInUser.getId())) {

                throw new UnauthorizedActionException(
                        "This audit is not assigned to you");
            }
        }

        // -----------------------------------------------------
        // Set actual audit entity
        // -----------------------------------------------------

        finding.setAudit(audit);

        // -----------------------------------------------------
        // Save finding
        // -----------------------------------------------------

        return findingRepository.save(finding);
    }

    // =========================================================
    // GET FINDING BY ID
    // =========================================================

    @Override
    public Finding getFindingById(Long id) {

        Finding finding = findingRepository.findById(id)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Finding not found with id: " + id));

        User loggedInUser = getLoggedInUser();

        String role = loggedInUser.getRole() != null
                ? loggedInUser.getRole().getName()
                : null;

        // -----------------------------------------------------
        // ADMIN can view any finding
        // -----------------------------------------------------

        if ("ADMIN".equalsIgnoreCase(role)) {
            return finding;
        }

        // -----------------------------------------------------
        // AUDITOR can view findings of assigned audits only
        // -----------------------------------------------------

        if ("AUDITOR".equalsIgnoreCase(role)) {

            if (finding.getAudit() == null ||
                    finding.getAudit().getAuditor() == null ||
                    !finding.getAudit()
                            .getAuditor()
                            .getId()
                            .equals(loggedInUser.getId())) {

                throw new UnauthorizedActionException(
                        "This finding does not belong to your assigned audit");
            }

            return finding;
        }

        throw new UnauthorizedActionException(
                "You are not authorized to view this finding");
    }

    // =========================================================
    // GET ALL FINDINGS
    // =========================================================

    @Override
    public List<Finding> getAllFindings() {

        User loggedInUser = getLoggedInUser();

        String role = loggedInUser.getRole() != null
                ? loggedInUser.getRole().getName()
                : null;

        // -----------------------------------------------------
        // ADMIN → All findings
        // -----------------------------------------------------

        if ("ADMIN".equalsIgnoreCase(role)) {

            return findingRepository.findAll();
        }

        // -----------------------------------------------------
        // AUDITOR → Only assigned audit findings
        // -----------------------------------------------------

        if ("AUDITOR".equalsIgnoreCase(role)) {

            List<Finding> allFindings =
                    findingRepository.findAll();

            return allFindings.stream()
                    .filter(finding ->
                            finding.getAudit() != null &&
                                    finding.getAudit().getAuditor() != null &&
                                    finding.getAudit()
                                            .getAuditor()
                                            .getId()
                                            .equals(loggedInUser.getId()))
                    .toList();
        }

        throw new UnauthorizedActionException(
                "You are not authorized to view findings");
    }

    // =========================================================
    // UPDATE FINDING
    // =========================================================

    @Override
    public Finding updateFinding(
            Long id,
            Finding finding) {

        // getFindingById() already performs authorization
        Finding existingFinding =
                getFindingById(id);

        existingFinding.setTitle(
                finding.getTitle());

        existingFinding.setDescription(
                finding.getDescription());

        existingFinding.setSeverity(
                finding.getSeverity());

        existingFinding.setStatus(
                finding.getStatus());

        return findingRepository.save(
                existingFinding);
    }

    // =========================================================
    // DELETE FINDING
    // =========================================================

    @Override
    public void deleteFinding(Long id) {

        // getFindingById() checks authorization
        Finding existingFinding =
                getFindingById(id);

        findingRepository.delete(existingFinding);
    }

    // =========================================================
    // GET FINDINGS BY STATUS
    // =========================================================

    @Override
    public List<Finding> getFindingsByStatus(
            String status) {

        User loggedInUser = getLoggedInUser();

        String role = loggedInUser.getRole() != null
                ? loggedInUser.getRole().getName()
                : null;

        List<Finding> findings =
                findingRepository.findByStatus(status);

        // -----------------------------------------------------
        // ADMIN → All findings
        // -----------------------------------------------------

        if ("ADMIN".equalsIgnoreCase(role)) {

            return findings;
        }

        // -----------------------------------------------------
        // AUDITOR → Assigned audit findings only
        // -----------------------------------------------------

        if ("AUDITOR".equalsIgnoreCase(role)) {

            return findings.stream()
                    .filter(finding ->
                            finding.getAudit() != null &&
                                    finding.getAudit().getAuditor() != null &&
                                    finding.getAudit()
                                            .getAuditor()
                                            .getId()
                                            .equals(loggedInUser.getId()))
                    .toList();
        }

        throw new UnauthorizedActionException(
                "You are not authorized to view findings");
    }

    // =========================================================
    // GET FINDINGS BY SEVERITY
    // =========================================================

    @Override
    public List<Finding> getFindingsBySeverity(
            String severity) {

        User loggedInUser = getLoggedInUser();

        String role = loggedInUser.getRole() != null
                ? loggedInUser.getRole().getName()
                : null;

        List<Finding> findings =
                findingRepository.findBySeverity(severity);

        // -----------------------------------------------------
        // ADMIN → All findings
        // -----------------------------------------------------

        if ("ADMIN".equalsIgnoreCase(role)) {

            return findings;
        }

        // -----------------------------------------------------
        // AUDITOR → Assigned audit findings only
        // -----------------------------------------------------

        if ("AUDITOR".equalsIgnoreCase(role)) {

            return findings.stream()
                    .filter(finding ->
                            finding.getAudit() != null &&
                                    finding.getAudit().getAuditor() != null &&
                                    finding.getAudit()
                                            .getAuditor()
                                            .getId()
                                            .equals(loggedInUser.getId()))
                    .toList();
        }

        throw new UnauthorizedActionException(
                "You are not authorized to view findings");
    }
}