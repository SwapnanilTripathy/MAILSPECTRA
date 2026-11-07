import React, { createContext, useContext, useState } from 'react';
import { maskAnalysis } from '../utils/privacy';
const PrivacyContext = createContext({ masked: false, setMasked: () => {} });
export function PrivacyProvider({ children }) {
  const [masked, update] = useState(() => sessionStorage.getItem('mailspectra_mask') === 'true');
  const setMasked = value => { update(value); sessionStorage.setItem('mailspectra_mask', String(value)); };
  return <PrivacyContext.Provider value={{ masked, setMasked }}>{children}</PrivacyContext.Provider>;
}
export function usePrivacy() { return useContext(PrivacyContext); }
export function useMasked(value) { return usePrivacy().masked ? maskAnalysis(value) : value; }
