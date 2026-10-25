import type { SecurityProfile } from "../types/ipc";

class ProfileStore {
  activeProfile = $state<SecurityProfile>("standard");
  mdmLocked = $state<boolean>(false);
  isSwitching = $state<boolean>(false);

  setProfile(profile: SecurityProfile, locked: boolean = false) {
    this.activeProfile = profile;
    this.mdmLocked = locked;
  }
}

export const profileStore = new ProfileStore();
