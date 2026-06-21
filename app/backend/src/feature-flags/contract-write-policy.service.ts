import { Injectable, Logger, ForbiddenException } from '@nestjs/common';

import { AppConfigService } from '../config';
import { AuditService } from '../audit/audit.service';
import { FeatureFlagsService } from './feature-flags.service';
import {
  CONTRACT_WRITES_DISABLED_CODE,
  CONTRACT_WRITES_DISABLED_MESSAGE,
  TESTNET_CONTRACT_WRITES_FLAG,
  MAINNET_CONTRACT_WRITES_FLAG,
} from './contract-write-kill-switch.constants';

export enum ContractWriteOperation {
  REFUND_INITIATE = 'refund.initiate',
  REFUND_APPROVE = 'refund.approve',
  REFUND_REJECT = 'refund.reject',
  CONTRACT_PUBLISH = 'contract.publish',
  CONTRACT_ROLLBACK = 'contract.rollback',
  CONTRACT_DEPLOY = 'contract.deploy',
  CONTRACT_UPGRADE = 'contract.upgrade',
}

export interface ContractWritePolicyCheck {
  allowed: boolean;
  reason?: string;
  flag?: string;
}

export interface ContractWriteAuditContext {
  actorId: string;
  operation: ContractWriteOperation;
  contractId?: string;
  network: string;
  metadata?: Record<string, unknown>;
}

/**
 * Shared service for enforcing contract write safety policies across all backend write paths.
 *
 * This service centralizes policy checks for operations that can submit, deploy, upgrade,
 * or mutate contract state. It ensures consistent enforcement of kill switches and audit logging.
 */
@Injectable()
export class ContractWritePolicyService {
  private readonly logger = new Logger(ContractWritePolicyService.name);

  constructor(
    private readonly config: AppConfigService,
    private readonly flags: FeatureFlagsService,
    private readonly audit: AuditService,
  ) {}

  /**
   * Check if a contract write operation is allowed based on network and kill switch state.
   *
   * @param operation - The type of contract write operation
   * @param actorId - The ID of the actor attempting the operation
   * @param context - Additional context for audit logging
   * @throws ForbiddenException if the operation is blocked by policy
   */
  async checkWritePolicy(
    operation: ContractWriteOperation,
    actorId: string,
    context?: Partial<ContractWriteAuditContext>,
  ): Promise<void> {
    const network = this.config.network;
    const isTestnet = this.config.isTestnet;

    // Determine which flag to check based on network and operation type
    const flagKey = isTestnet ? TESTNET_CONTRACT_WRITES_FLAG : MAINNET_CONTRACT_WRITES_FLAG;

    // Evaluate the flag (fresh read for testnet to ensure kill switch takes effect immediately)
    const result = isTestnet
      ? await this.flags.evaluateFlagFresh(flagKey, { userId: actorId })
      : await this.flags.evaluateFlag(flagKey, { userId: actorId });

    const auditContext: ContractWriteAuditContext = {
      actorId,
      operation,
      network,
      ...context,
    };

    if (!result.enabled) {
      // Log the blocked operation
      await this.audit.log(
        actorId,
        'contract_write_policy.blocked',
        operation,
        {
          reason: result.reason,
          flag: flagKey,
          network,
          ...context,
        },
      );

      this.logger.warn(
        `Contract write blocked: operation=${operation} actor=${actorId} ` +
          `network=${network} flag=${flagKey} reason=${result.reason}`,
      );

      throw new ForbiddenException({
        code: CONTRACT_WRITES_DISABLED_CODE,
        error: CONTRACT_WRITES_DISABLED_CODE,
        flag: flagKey,
        reason: result.reason,
        operation,
        network,
        message: isTestnet
          ? CONTRACT_WRITES_DISABLED_MESSAGE
          : `Contract write operation '${operation}' is disabled on mainnet. Enable flag "${flagKey}" to proceed.`,
      });
    }

    // Log the allowed operation for audit trail
    await this.audit.log(
      actorId,
      'contract_write_policy.allowed',
      operation,
      {
        flag: flagKey,
        network,
        ...context,
      },
    );

    this.logger.log(
      `Contract write allowed: operation=${operation} actor=${actorId} network=${network}`,
    );
  }

  /**
   * Check if a contract write operation is allowed without throwing an exception.
   *
   * @param operation - The type of contract write operation
   * @param actorId - The ID of the actor attempting the operation
   * @returns Policy check result
   */
  async checkWritePolicySafe(
    operation: ContractWriteOperation,
    actorId: string,
  ): Promise<ContractWritePolicyCheck> {
    const isTestnet = this.config.isTestnet;
    const flagKey = isTestnet ? TESTNET_CONTRACT_WRITES_FLAG : MAINNET_CONTRACT_WRITES_FLAG;

    const result = isTestnet
      ? await this.flags.evaluateFlagFresh(flagKey, { userId: actorId })
      : await this.flags.evaluateFlag(flagKey, { userId: actorId });

    return {
      allowed: result.enabled,
      reason: result.reason,
      flag: flagKey,
    };
  }

  /**
   * Check if contract writes are currently disabled for the active network.
   *
   * @returns true if contract writes are disabled
   */
  async areContractWritesDisabled(): Promise<boolean> {
    const isTestnet = this.config.isTestnet;
    const flagKey = isTestnet ? TESTNET_CONTRACT_WRITES_FLAG : MAINNET_CONTRACT_WRITES_FLAG;

    const result = isTestnet
      ? await this.flags.evaluateFlagFresh(flagKey, {})
      : await this.flags.evaluateFlag(flagKey, {});

    return !result.enabled;
  }
}
