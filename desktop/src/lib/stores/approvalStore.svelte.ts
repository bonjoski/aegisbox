import type { PendingApproval, ApprovalScope } from "../types/ipc";

class ApprovalStore {
  // Svelte 5 reactive rune
  pending = $state<PendingApproval[]>([]);
  activeApproval = $derived(this.pending.length > 0 ? this.pending[0] : null);
  isLoading = $state(false);

  setPending(list: PendingApproval[]) {
    this.pending = list;
  }

  addApproval(item: PendingApproval) {
    if (!this.pending.some((p) => p.interceptId === item.interceptId)) {
      this.pending = [...this.pending, item];
    }
  }

  removeApproval(interceptId: string) {
    this.pending = this.pending.filter((p) => p.interceptId !== interceptId);
  }
}

export const approvalStore = new ApprovalStore();
