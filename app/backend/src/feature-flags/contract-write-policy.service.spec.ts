import { Test, TestingModule } from '@nestjs/testing';
import { ForbiddenException } from '@nestjs/common';

import { AppConfigService } from '../config';
import { AuditService } from '../audit/audit.service';
import { FeatureFlagsService } from './feature-flags.service';
import { ContractWritePolicyService, ContractWriteOperation } from './contract-write-policy.service';

describe('ContractWritePolicyService', () => {
  let service: ContractWritePolicyService;
  let configService: AppConfigService;
  let flagsService: FeatureFlagsService;
  let auditService: AuditService;

  const mockConfigService = {
    network: 'testnet',
    isTestnet: true,
  };

  const mockFlagsService = {
    evaluateFlag: jest.fn(),
    evaluateFlagFresh: jest.fn(),
  };

  const mockAuditService = {
    log: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ContractWritePolicyService,
        {
          provide: AppConfigService,
          useValue: mockConfigService,
        },
        {
          provide: FeatureFlagsService,
          useValue: mockFlagsService,
        },
        {
          provide: AuditService,
          useValue: mockAuditService,
        },
      ],
    }).compile();

    service = module.get<ContractWritePolicyService>(ContractWritePolicyService);
    configService = module.get<AppConfigService>(AppConfigService);
    flagsService = module.get<FeatureFlagsService>(FeatureFlagsService);
    auditService = module.get<AuditService>(AuditService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('checkWritePolicy', () => {
    it('should allow operation when flag is enabled', async () => {
      mockFlagsService.evaluateFlagFresh.mockResolvedValue({ enabled: true, reason: 'test' });

      await expect(
        service.checkWritePolicy(ContractWriteOperation.CONTRACT_PUBLISH, 'actor-123'),
      ).resolves.not.toThrow();

      expect(mockAuditService.log).toHaveBeenCalledWith(
        'actor-123',
        'contract_write_policy.allowed',
        ContractWriteOperation.CONTRACT_PUBLISH,
        expect.objectContaining({
          flag: 'testnet.contract_writes',
          network: 'testnet',
        }),
      );
    });

    it('should block operation when flag is disabled', async () => {
      mockFlagsService.evaluateFlagFresh.mockResolvedValue({
        enabled: false,
        reason: 'kill switch active',
      });

      await expect(
        service.checkWritePolicy(ContractWriteOperation.CONTRACT_PUBLISH, 'actor-123'),
      ).rejects.toThrow(ForbiddenException);

      expect(mockAuditService.log).toHaveBeenCalledWith(
        'actor-123',
        'contract_write_policy.blocked',
        ContractWriteOperation.CONTRACT_PUBLISH,
        expect.objectContaining({
          flag: 'testnet.contract_writes',
          network: 'testnet',
          reason: 'kill switch active',
        }),
      );
    });

    it('should use evaluateFlagFresh for testnet', async () => {
      mockFlagsService.evaluateFlagFresh.mockResolvedValue({ enabled: true, reason: 'test' });

      await service.checkWritePolicy(ContractWriteOperation.CONTRACT_DEPLOY, 'actor-123');

      expect(mockFlagsService.evaluateFlagFresh).toHaveBeenCalledWith(
        'testnet.contract_writes',
        { userId: 'actor-123' },
      );
      expect(mockFlagsService.evaluateFlag).not.toHaveBeenCalled();
    });

    it('should use evaluateFlag for mainnet', async () => {
      mockConfigService.isTestnet = false;
      mockConfigService.network = 'mainnet';
      mockFlagsService.evaluateFlag.mockResolvedValue({ enabled: true, reason: 'test' });

      await service.checkWritePolicy(ContractWriteOperation.CONTRACT_PUBLISH, 'actor-123');

      expect(mockFlagsService.evaluateFlag).toHaveBeenCalledWith(
        'mainnet.contract_writes',
        { userId: 'actor-123' },
      );
      expect(mockFlagsService.evaluateFlagFresh).not.toHaveBeenCalled();
    });

    it('should include metadata in audit log', async () => {
      mockFlagsService.evaluateFlagFresh.mockResolvedValue({ enabled: true, reason: 'test' });

      await service.checkWritePolicy(
        ContractWriteOperation.CONTRACT_PUBLISH,
        'actor-123',
        {
          contractId: 'contract-abc',
          metadata: { contractName: 'RustAcademy' },
        },
      );

      expect(mockAuditService.log).toHaveBeenCalledWith(
        'actor-123',
        'contract_write_policy.allowed',
        ContractWriteOperation.CONTRACT_PUBLISH,
        expect.objectContaining({
          contractId: 'contract-abc',
          metadata: { contractName: 'RustAcademy' },
        }),
      );
    });
  });

  describe('checkWritePolicySafe', () => {
    it('should return allowed=true when flag is enabled', async () => {
      mockFlagsService.evaluateFlagFresh.mockResolvedValue({ enabled: true, reason: 'test' });

      const result = await service.checkWritePolicySafe(
        ContractWriteOperation.CONTRACT_PUBLISH,
        'actor-123',
      );

      expect(result).toEqual({
        allowed: true,
        reason: 'test',
        flag: 'testnet.contract_writes',
      });
    });

    it('should return allowed=false when flag is disabled', async () => {
      mockFlagsService.evaluateFlagFresh.mockResolvedValue({
        enabled: false,
        reason: 'kill switch active',
      });

      const result = await service.checkWritePolicySafe(
        ContractWriteOperation.CONTRACT_PUBLISH,
        'actor-123',
      );

      expect(result).toEqual({
        allowed: false,
        reason: 'kill switch active',
        flag: 'testnet.contract_writes',
      });
    });
  });

  describe('areContractWritesDisabled', () => {
    it('should return true when flag is disabled', async () => {
      mockFlagsService.evaluateFlagFresh.mockResolvedValue({
        enabled: false,
        reason: 'kill switch active',
      });

      const result = await service.areContractWritesDisabled();

      expect(result).toBe(true);
    });

    it('should return false when flag is enabled', async () => {
      mockFlagsService.evaluateFlagFresh.mockResolvedValue({ enabled: true, reason: 'test' });

      const result = await service.areContractWritesDisabled();

      expect(result).toBe(false);
    });
  });
});
