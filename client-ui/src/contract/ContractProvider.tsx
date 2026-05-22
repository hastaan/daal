// ContractProvider.tsx — React context wrapping the active D2Contract.
//
// Boot path:
//   main.tsx -> <ContractProvider> -> <App />
//   ContractProvider picks the backend once (via ../backends/index.ts)
//   and exposes it through useContract().
//
// Screens never import a specific backend. They call
//   const contract = useContract();
//   const summary = await contract.connectionSummary();

import { createContext, useContext, type ReactNode } from 'react';
import type { D2Contract } from './D2Contract';
import { activeContract } from '../backends';

const ContractContext = createContext<D2Contract | null>(null);

export function ContractProvider({ children }: { children: ReactNode }) {
    return (
        <ContractContext.Provider value={activeContract}>
            {children}
        </ContractContext.Provider>
    );
}

export function useContract(): D2Contract {
    const c = useContext(ContractContext);
    if (!c) {
        throw new Error(
            'useContract must be called inside <ContractProvider>. ' +
            'Did you forget to wrap your app?',
        );
    }
    return c;
}
