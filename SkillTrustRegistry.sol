// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SkillTrustRegistry
/// @notice ระบบออกและตรวจสอบใบรับรองดิจิทัลของ SkillTrust Academy (ตามโจทย์ข้อ 3)
///         1. ผู้ดูแลระบบลงทะเบียนหลักสูตร (createCourse)
///         2. ผู้ออกใบรับรองที่ได้รับสิทธิ์ออกใบ (issueCertificate)
///         3. เก็บ hash ของไฟล์ใบรับรองบน chain
///         4. ตรวจสอบความถูกต้อง (verifyCertificate) โดยไม่มีค่าใช้จ่าย gas
///         5. เพิกถอนใบรับรองและยังเก็บประวัติไว้
///         6. ดูประวัติใบรับรองของผู้รับ (getCertificateIdsOf)
///         ไม่เก็บชื่อหรือข้อมูลส่วนบุคคลบน chain
contract SkillTrustRegistry {
    enum Status {
        None,
        Active,
        Revoked
    }

    struct Course {
        string name;
        uint64 startDate;
        bool exists;
    }

    struct Certificate {
        string courseCode;
        bytes32 fileHash;   // SHA-256 ของไฟล์ใบรับรอง
        address recipient;  // wallet ของผู้รับ (ไม่ใช่ชื่อ)
        address issuer;
        uint64 issuedAt;
        Status status;
    }

    address public immutable admin;
    mapping(address => bool) public isIssuer;
    mapping(string => Course) private courses;
    mapping(string => Certificate) private certs;
    mapping(bytes32 => string) public certIdByFileHash; // กันการใช้ hash ซ้ำ
    mapping(address => string[]) private idsOf;

    event IssuerSet(address indexed issuer, bool allowed, uint64 at);
    event CourseCreated(string courseCode, string name, uint64 startDate, address indexed by, uint64 at);
    event CertificateIssued(
        string certId,
        string courseCode,
        address indexed recipient,
        bytes32 fileHash,
        address indexed issuer,
        uint64 issuedAt
    );
    event CertificateRevoked(string certId, address indexed by, uint64 at);
    event Activity(address indexed actor, bytes32 indexed kind, bytes32 dataHash, uint64 at);

    error NotAdmin();
    error NotIssuer();
    error InvalidInput();
    error CourseExists();
    error CourseNotFound();
    error CertificateExists();
    error HashAlreadyUsed();
    error FutureIssueDate();
    error UnknownCertificate();
    error NotActive();
    error NotAllowedToRevoke();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    modifier onlyIssuer() {
        if (!isIssuer[msg.sender]) revert NotIssuer();
        _;
    }

    constructor() {
        admin = msg.sender;
        isIssuer[msg.sender] = true;
        emit IssuerSet(msg.sender, true, uint64(block.timestamp));
    }

    /// @notice มอบหรือยกเลิกสิทธิ์ผู้ออกใบรับรอง (เฉพาะผู้ดูแลระบบ)
    function setIssuer(address issuer, bool allowed) external onlyAdmin {
        isIssuer[issuer] = allowed;
        emit IssuerSet(issuer, allowed, uint64(block.timestamp));
    }

    /// @notice ลงทะเบียนหลักสูตร (เฉพาะผู้ดูแลระบบ)
    function createCourse(string memory courseCode, string memory name, uint64 startDate) external onlyAdmin {
        if (bytes(courseCode).length == 0 || bytes(name).length == 0) revert InvalidInput();
        if (courses[courseCode].exists) revert CourseExists();
        courses[courseCode] = Course(name, startDate, true);
        emit CourseCreated(courseCode, name, startDate, msg.sender, uint64(block.timestamp));
    }

    /// @notice ดูข้อมูลหลักสูตร ใครก็อ่านได้
    function getCourse(string memory courseCode) external view returns (string memory name, uint64 startDate, bool exists) {
        Course storage c = courses[courseCode];
        return (c.name, c.startDate, c.exists);
    }

    /// @notice ออกใบรับรอง (เฉพาะผู้ออกใบรับรองที่ได้รับสิทธิ์)
    function issueCertificate(
        string memory certId,
        string memory courseCode,
        address recipient,
        bytes32 fileHash,
        uint64 issuedAt
    ) external onlyIssuer {
        if (bytes(certId).length == 0 || recipient == address(0)) revert InvalidInput();
        if (!courses[courseCode].exists) revert CourseNotFound();
        if (certs[certId].status != Status.None) revert CertificateExists();
        if (bytes(certIdByFileHash[fileHash]).length != 0) revert HashAlreadyUsed();
        if (issuedAt > block.timestamp) revert FutureIssueDate();

        certs[certId] = Certificate(courseCode, fileHash, recipient, msg.sender, issuedAt, Status.Active);
        certIdByFileHash[fileHash] = certId;
        idsOf[recipient].push(certId);
        emit CertificateIssued(certId, courseCode, recipient, fileHash, msg.sender, issuedAt);
    }

    /// @notice ตรวจความถูกต้อง: valid = ยังมีผล, hashMatches = hash ของไฟล์ที่ส่งมาตรงกับที่ออกไว้
    function verifyCertificate(string memory certId, bytes32 fileHash)
        external
        view
        returns (bool valid, bool hashMatches, address recipient, address issuer, uint64 issuedAt)
    {
        Certificate storage c = certs[certId];
        return (c.status == Status.Active, c.fileHash == fileHash && c.status != Status.None, c.recipient, c.issuer, c.issuedAt);
    }

    /// @notice เพิกถอนใบรับรอง ทำได้โดยผู้ออกใบรับรองนั้นหรือผู้ดูแลระบบ (ประวัติยังอยู่)
    function revokeCertificate(string memory certId) external onlyIssuer {
        Certificate storage c = certs[certId];
        if (c.status == Status.None) revert UnknownCertificate();
        if (c.status != Status.Active) revert NotActive();
        if (msg.sender != c.issuer && msg.sender != admin) revert NotAllowedToRevoke();
        c.status = Status.Revoked;
        emit CertificateRevoked(certId, msg.sender, uint64(block.timestamp));
    }

    /// @notice ดูข้อมูลใบรับรองหนึ่งใบ ใครก็อ่านได้
    function getCertificate(string memory certId)
        external
        view
        returns (Status status, string memory courseCode, bytes32 fileHash, address recipient, address issuer, uint64 issuedAt)
    {
        Certificate storage c = certs[certId];
        return (c.status, c.courseCode, c.fileHash, c.recipient, c.issuer, c.issuedAt);
    }

    /// @notice ประวัติรหัสใบรับรองของผู้รับ รวมใบที่ถูกเพิกถอนแล้ว ใครก็อ่านได้
    function getCertificateIdsOf(address recipient) external view returns (string[] memory) {
        return idsOf[recipient];
    }

    /// @notice บันทึกกิจกรรมอื่นของระบบ ใครก็เรียกได้ แต่ actor คือ msg.sender เสมอ
    function record(bytes32 kind, bytes32 dataHash) external {
        emit Activity(msg.sender, kind, dataHash, uint64(block.timestamp));
    }
}
