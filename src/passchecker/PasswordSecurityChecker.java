package passchecker;

import java.io.BufferedReader;
import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.stream.IntStream;

/**
 * La classe PasswordSecurityChecker serve per cercare di forzare una password
 * passata dall'utente usando tre modi differeti: dictionary attack, brute force
 * e cercare di forzarla usando gli argomenti che l'utente passa insieme alla 
 * password, ovvero: nome, cognome, data di nascita e una parola extra. Tentando
 * diverse combinazioni tra esse, per provare a forzare la password.
 * @author Xavier Horisberger
 * @verions 30.09.2021
 */
public class PasswordSecurityChecker {
    
    /*
        Ordine argomenti: Nome, Cognome, DataNasicta, ParolaExtra
        La data deve essere in questo formato: gg.mm.aaaa
    */
    private List<String> arguments = new LinkedList<>();
    private List<String> argumentCombos = new LinkedList<>();
    private List<String> argumentCombosTemp = new LinkedList<>();
    
    private List<String> mostKnownPasswords = new LinkedList<>();

    private final int MAX_LEN = 20;
    private String password;
    private String foundPassword;
    
    private long time;
    private long tries;
    
    private boolean found;
    
    private List<String> characters = new ArrayList<>();
    
    /**
     * Costruttore che istanzia un Oggetto di tipo PasswordSecurityChecker.
     * @param arguments argomenti passati da linea di comando. Il primo 
     * argomento è la password, gli altri verranno salvati nella lista arguments
     * e utilizzati per provare a scoprire la password (solo i primi 4 di essi).
     */
    public PasswordSecurityChecker(String[] arguments) 
        throws IllegalArgumentException{
        
        if(arguments.length >= 1){
            //password
            if(arguments[0].length() <= MAX_LEN){
                password = arguments[0];
            }else{
                String err = "Passare una password con lunghezza";
                err += "minore di: " + MAX_LEN;
                throw new IllegalArgumentException(err);
            }
            
            //password più conosciute
            loadMostKnownPasswords();
            
            //Primi 4 argomenti
            this.arguments = arrayToList(arguments);
            this.arguments.remove(0);
            if(this.arguments.size() >= 5){
                for(int i = 4;i < this.arguments.size();i++){
                    this.arguments.remove(i);
                }
            }
            //Creare combinazioni con gli argomenti
            if(!this.arguments.isEmpty()){
                long start = System.currentTimeMillis();
                makeCombos();
                time += System.currentTimeMillis()-start;
            }
            
            //Caratteri per brute force
            String string = new String(IntStream.rangeClosed(33,255).toArray(),
                0,223);
            characters = arrayToList(string.split(""));	
        }else{
            String err = "Passare un array contenente almeno un dato";
            throw new IllegalArgumentException(err);
        }
    }
    
    /**
     * Questo metodo trasforma un array di stringhe in una lista di stringhe.
     * @param array array di stringhe da trasformare.
     * @return lista contenente gli stessi dati dell'array passato.
     */
    private List<String> arrayToList(String[] array){
        List<String> list = new LinkedList<>();
        list.addAll(Arrays.asList(array));
        return list;
    }
    
    /**
     * Questo metodo serve per inserire il contenuto del file 
     * 100000-most-known-passwords.txt in una lista. Questo file contiene le
     * 100000 password più utilizzate al mondo.
     */
    private void loadMostKnownPasswords(){
        try{
            String path = "../data/100000-most-known-passwords.txt";
            String inputLine;
            InputStream in = getClass().getResourceAsStream(path);
            InputStreamReader isr = new InputStreamReader(in);
            BufferedReader reader = new BufferedReader(isr);
            while ((inputLine = reader.readLine()) != null) {
                mostKnownPasswords.add(inputLine);
            }
            reader.close();
        }catch(IOException e){
            System.err.println("Error reading file");
        }
    }
    
    /**
     * Questo metodo serve a stampare i tentativi e tempo impiegati a scoprire
     * la password.
     */
    private void printTriesAndTime(){
        System.out.print("\r");
        System.out.print("Tries: " + tries + " Time: " + time  + " ms");
        System.out.print("\r");
    }
    
    /**
     * Questo metodo serve a fare la stampa finale una volta trovata la 
     * password.
     */
    public void finalPrint(){
        System.out.print("Password trovata: " + foundPassword);
        System.out.print(" Tentativi: " + tries + " Tempo: ");
        System.out.print(time);
    }
    
    /**
     * Questo metodo riceve una stringa e ritorna una lista contenente la prima
     * lettare della stringa all'indice 0, se possibile le prime due 
     * all'indice 1, e infine se possibile le prime tre all'indice 2.
     * @param word parola da suddividere
     * @return lista contenente le varie suddivisioni della stringa
     */
    private List<String> addSubStrings(String word){
        List<String> a = new LinkedList<>();
        a.add(word.substring(0,1));
        if(word.length() >= 3){
            a.add(word.substring(0,3));
            a.add(word.substring(0,2));
        }else{
            a.add(word.substring(0,2));
        }
        for(String i : a){
            addCombos("","",i);
        }
        return a;
    }
    
    /**
     * Questo metodo serve a fare diverse combinazioni tra il nome, cognome e
     * la parola passata, in base a cosa viene passato. Queste combinazioni
     * vengono inserite nella lista di combinazioni temporane.
     * @param n nome
     * @param s cognome
     * @param w parola
     */
    private void addCombos(String n, String s, String w){
        if(n.equals("")){
            argumentCombosTemp.add(w);
            argumentCombosTemp.add(w.toLowerCase());
            argumentCombosTemp.add(w.toUpperCase());
        }else if(s.equals("")){
            argumentCombosTemp.add(n+w);
            argumentCombosTemp.add(n.toLowerCase()+w);
            argumentCombosTemp.add(w+n);
            argumentCombosTemp.add(w+n.toLowerCase());
        }else{
            String[] a = {n,s};
            for(String i : a){
                for(String j : a){
                    argumentCombosTemp.add(i+j+w);
                    argumentCombosTemp.add(w+i+j);
                }
            }
        }
    }
    
    /**
     * Questo metodo serve a creare diverse combinazioni sfruttando i quattro
     * argometni passati dall'utente. Che verranno poi utilizzate 
     * nell'argumentsForce.
     */
    private void makeCombos(){
        List<String> firstLettersName = new LinkedList<>();
        
        //Variazioni per ogni argomento in maiscolo, minuscolo e originale
        for(String i : arguments){
            addCombos("","",i);
        }
        //Combinazioni tra ogni argomento minuscolo, maiuscolo e originale
        for(String i : argumentCombos){
            for(String j : argumentCombos){
                argumentCombosTemp.add(i+j);
            }
        }
        argumentCombos.addAll(argumentCombosTemp);
        argumentCombosTemp.clear();
        
        if(arguments.size() >= 2){
            firstLettersName = new LinkedList<>(addSubStrings(arguments.get(0)));
            firstLettersName.addAll(addSubStrings(arguments.get(1)));
            firstLettersName = new LinkedList<>(argumentCombosTemp);
            argumentCombosTemp.clear();
        }else{
            firstLettersName = new LinkedList<>(addSubStrings(arguments.get(0)));
            argumentCombosTemp.clear();
        }
        
        System.out.println("");
        for(String i : argumentCombos){
            for(String j : firstLettersName){
                addCombos(j,"",i);
                for(String h : firstLettersName){
                    addCombos(j,h,i);
                }
            }
        }
        argumentCombos.addAll(argumentCombosTemp);
        argumentCombosTemp.clear();
        
        String[] date = new String[0];
        if(arguments.size() >= 3){
            date = arguments.get(2).split("[.]");
        }
        if(arguments.size() >= 3 && date.length == 3){
            //Combinazioni con giorno, mese e anno di nascita
            for(String i : argumentCombos){
                argumentCombosTemp.add(i+date[0]);
                argumentCombosTemp.add(i+date[1]);
                argumentCombosTemp.add(i+date[2]);
                argumentCombosTemp.add(i+date[0]+date[1]);
                argumentCombosTemp.add(i+date[0]+date[1]+date[2]);
            }
            argumentCombos.addAll(argumentCombosTemp);
            argumentCombosTemp.clear();
            
            argumentCombos.add(date[0]+date[1]);
            argumentCombos.add(date[0]+date[1]+date[2]);
        }
    }
    
    /**
     * Questo metodo viene richiamato alla fine di un force, una volta trovata
     * la password.
     * @param s password trovata
     */
    private void endForce(String s){
        tries++;
        foundPassword = s;
        found = true;
    }
    
    /**
     * Questo metodo serve a scoprire la password usando la lista di password 
     * più utilizzate al mondo.Mentre lavora stampa anche i tentativi e tempo
     * impiegato complessivamente dal programma.
     */
    protected void dictionaryForce() {
        long start = System.currentTimeMillis();
        for(String s : mostKnownPasswords){
            tries++;
            if(s.equals(password)){
                endForce(s);
                return;
            }
            if(tries % 1000 == 0){
                printTriesAndTime();
            }
        }
        time += System.currentTimeMillis()-start;
    }
    
    /**
     * Questo metodo serve a scoprire la password usando un attacco brute force.
     * @param keys lettera da cui parte il brute force, in teoria dovrebbe venir
     * passato un "" all'inizo.
     */
    protected void bruteForceForce(String keys){
        long start = System.currentTimeMillis();
        if(keys.length() < MAX_LEN){
            for(String c : characters){
                tries++;
                if(!found && (keys + c).equals(password)){
                    endForce(keys + c);
                    return;
                }else if(!found){
                    bruteForceForce(keys + c);
                    if(tries % 100000 == 0){
                        printTriesAndTime();
                    }
                }
            }
        }
        time += System.currentTimeMillis()-start;
    }
    
    /**
     * Questo metodo prova a scoprire la password usando la lista di argomenti 
     * passata dall'utente.
     */
    protected void argumentsForce(){
        if(!arguments.isEmpty()){
            long start = System.currentTimeMillis();
            for(String i : argumentCombos){
                if(i.equals(password)){
                    endForce(i);
                    return;
                }
                tries++;
                if(tries % 100 == 0){
                    printTriesAndTime();
                }
            }
            time += System.currentTimeMillis()-start;
        }
    }
    
    /**
     * Questo è il metodo richiamato per cercare di trovare la password, 
     * utilizzando tutti i force creati.
     */
    public void findPassword(){
        argumentsForce();
        System.out.print("");
        if(found){
            finalPrint();
            System.out.println();
        }else{
            dictionaryForce();
            System.out.print("");
            if(found){
                finalPrint();
            }else{
                bruteForceForce("");
                System.out.print("");
                if(found){
                    finalPrint();
                }
            }
        }
    }
    
    public static void main(String[] args) {
        try{
            PasswordSecurityChecker psc = new PasswordSecurityChecker(args);
            //psc.findPassword();
            //psc.argumentsForce();
            //psc.bruteForceForce("");
            /*if(psc.found){
                System.out.println("\rFound: " + psc.foundPassword + " Tries: " + psc.tries + " Time: " + psc.time);
            }else{
                System.out.println("\rnot found");
            }*/
            /*for(String s : psc.arguments){
                System.out.println(s);
            }*/
            /*System.out.println(psc.argumentCombos.size());
            for(String s : psc.argumentCombos){
                System.out.println(s);
            }*/
        }catch(IllegalArgumentException e){
            System.err.println(e.getMessage());
        }
    }
}