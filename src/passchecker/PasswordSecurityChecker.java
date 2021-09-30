package passchecker;

import java.util.LinkedList;
import java.util.List;
import java.util.ArrayList;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.nio.file.Paths;

/**
 *
 * @author Xavier Horisberger
 * @verions 30.09.2021
 */
public class PasswordSecurityChecker {
    
    private List<String> arguments  = new ArrayList<>();
    private List<String> mostKnownPasswords = new LinkedList<>();
    private String password;
    private int time;
    private int trys;
    
    /**
     * Costruttore che istanzia un Oggetto di tipo PasswordSecurityChecker.
     * @param arguments argomenti passati da linea di comando. Il primo 
     * argomento è la password, gli altri verranno salvati nella lista arguments
     * e utilizzati per provare a scoprire la password (solo i primi 4 di essi).
     */
    public PasswordSecurityChecker(String[] arguments){
        if(arguments.length == 1){
            loadMostKnownPasswords();
            password = arguments[0];
        }else if(arguments.length >= 1){
            loadMostKnownPasswords();
            password = arguments[0];
            this.arguments = arrayToList(arguments);
            //rimozione di password dalla lista di argomenti
            this.arguments.remove(0);
            //rimozione di tutti gli argomnenti passati tranne i primi 4.
            if(this.arguments.size() >= 5){
                for(int i = 4;i < this.arguments.size();i++){
                    this.arguments.remove(i);
                }
            }
        }else{
            System.out.println("Passare un array contenente almeno un dato");
        }
    }
    
    @Override
    public String toString(){
        String pass = "Password: " + password + "\n";
        String args = "Argomenti:\n";
        for(int i = 0;i < arguments.size();i++){
            args += arguments.get(i) + " ";
        }
        return pass + args;
    }
    
    /**
     * Questo metodo trasforma un array di stringhe in una lista di stringhe.
     * @param array array di stringhe da trasformare.
     * @return lista contenente gli stessi dati dell'array passato.
     */
    private List<String> arrayToList(String[] array){
        List<String> list = new LinkedList<>();
        for(int i = 0;i < array.length;i++){
            list.add(array[i]);
        }
        return list;
    }
    
    /**
     * Questo metodo serve per inserire il contenuto del file 
     * 100000-most-known-passwords.txt in una lista. Questo file contiene le
     * 100000 password più utilizzate al mondo.
     */
    private void loadMostKnownPasswords(){
        Path file = Paths.get("./100000-most-known-passwords.txt");
        // getClass().getResourceAsStream("/data/100000-most-known-passwords.txt");
        if(Files.exists(file) && Files.isReadable(file)){
            try{
                mostKnownPasswords = Files.readAllLines(file);
            }catch(IOException e){
                System.err.println("Errore");
                System.err.println(e.getStackTrace());
            }
	}else{
            System.out.println("File passato inesistente o non leggibile");
	}
    }
    
    /**
     * Questo metodo serve a stampare i tentativi e tempo impiegati a scoprire
     * la password.
     */
    private void printTrysAndTime(){
        System.out.print("\r");
        System.out.print("Tentativi: " + trys + " Tempo: " + time);
    }
    
    /**
     * Questo metodo serve a scoprire la password usando la lista di password 
     * più utilizzate al mondo.
     * @return un array contenente in prima posizione 1 se ha scoperto la
     * password o 0 se non l'ha scoperta, e in seconda posizione il tempo che ci
     * ha impiegato in millisecondi.
     */
    protected int[] dictionaryDecode(){
        int[] array = new int[2];
        
        
        
        return array;
    }
    
    /**
     * Questo metodo serve a scoprire la password usando la lista di argomenti 
     * passata dall'utente.
     * @return un array contenente in prima posizione 1 se ha scoperto la
     * password o 0 se non l'ha scoperta, e in seconda posizione il tempo che ci
     * ha impiegato in millisecondi.
     */
    protected int[] argumentsDecode(){
        int[] array = new int[2];
        
        
        
        return array;
    }
    
    /**
     * Questo metodo serve a scoprire la password usando un attacco brute force.
     * @return un array contenente in prima posizione il tempo che ci
     * ha impiegato in millisecondi, e in seconda posizione i tentativi che ci
     * ha impiegato.
     */
    protected int[] bruteForceDecode(){
        int[] array = new int[2];
        
        
        
        return array;
    }
    
    public static void main(String[] args) {
        PasswordSecurityChecker psc = new PasswordSecurityChecker(args);
        
        /*for(int i = 0;i < psc.mostKnownPasswords.size();i++){
            System.out.println(psc.mostKnownPasswords.get(i));
        }*/
        
        for(String s : psc.mostKnownPasswords){
            System.out.println(s);
	}
    }
}
